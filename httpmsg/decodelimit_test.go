// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"bytes"
	"errors"
	"runtime"
	"runtime/metrics"
	"strings"
	"testing"

	netencoding "github.com/zchee/mitmproxy-go/internal/netutil/encoding"
)

// setDecodeLimit sets the process-global decode limit for one test and
// restores the previous value when the test ends. Callers must not call
// t.Parallel.
func setDecodeLimit(t *testing.T, limit int64) {
	t.Helper()
	previous := SetDecodeLimit(limit)
	t.Cleanup(func() { SetDecodeLimit(previous) })
}

// latin1 returns b decoded as Latin-1, each byte becoming the rune of its
// value, the fallback TextOrRaw uses when nothing declares a character set.
func latin1(b []byte) string {
	var s strings.Builder
	s.Grow(len(b))
	for _, c := range b {
		s.WriteRune(rune(c))
	}
	return s.String()
}

// gzipBody returns size zero bytes gzip-encoded.
func gzipBody(t *testing.T, size int) []byte {
	t.Helper()
	raw, err := netencoding.Encode(make([]byte, size), "gzip")
	if err != nil {
		t.Fatalf("Encode(gzip) error: %v", err)
	}
	return raw
}

// gzipMessage returns a message whose gzip body decodes to size zero bytes.
func gzipMessage(t *testing.T, size int) *Message {
	t.Helper()
	return &Message{
		Headers:    hdrs("content-encoding", "gzip"),
		RawContent: gzipBody(t, size),
	}
}

func TestSetDecodeLimit(t *testing.T) {
	const bound = 1 << 20
	if got := DecodeLimit(); got != defaultDecodeLimit {
		t.Fatalf("DecodeLimit() = %d before any SetDecodeLimit call, want the %d default", got, defaultDecodeLimit)
	}
	setDecodeLimit(t, bound)
	if got := DecodeLimit(); got != bound {
		t.Errorf("DecodeLimit() = %d after SetDecodeLimit(%d), want %d", got, bound, bound)
	}
	if got := SetDecodeLimit(defaultDecodeLimit); got != bound {
		t.Errorf("SetDecodeLimit returned previous = %d, want %d", got, bound)
	}
}

// TestMessageDecodeLimit checks that every decode path treats a body over
// the limit as undecodable: Content and Text fail with an error wrapping
// the decoder's size-limit error, ContentOrRaw and TextOrRaw return the
// raw bytes, and under the default the same body decodes.
func TestMessageDecodeLimit(t *testing.T) {
	const decodedSize = 2 << 20
	tests := map[string]struct {
		limit   int64
		wantErr bool
	}{
		"error: 2 MiB body over a 1 MiB limit":       {limit: 1 << 20, wantErr: true},
		"error: zero limit bounds every body":        {limit: 0, wantErr: true},
		"error: negative limit behaves as zero":      {limit: -1, wantErr: true},
		"success: 2 MiB body under the default":      {limit: defaultDecodeLimit, wantErr: false},
		"success: limit of exactly the decoded size": {limit: decodedSize, wantErr: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			setDecodeLimit(t, tt.limit)
			m := gzipMessage(t, decodedSize)

			content, err := m.Content()
			text, textErr := m.Text()
			if !tt.wantErr {
				if err != nil || textErr != nil {
					t.Fatalf("Content() error = %v, Text() error = %v with limit %d, want success", err, textErr, tt.limit)
				}
				if !bytes.Equal(content, make([]byte, decodedSize)) {
					t.Errorf("Content() = %d bytes with limit %d, want the %d-byte decoded body", len(content), tt.limit, decodedSize)
				}
				if len(text) != decodedSize {
					t.Errorf("Text() = %d characters with limit %d, want %d", len(text), tt.limit, decodedSize)
				}
				return
			}
			for op, opErr := range map[string]error{"Content": err, "Text": textErr} {
				if !errors.Is(opErr, netencoding.ErrSizeLimit) {
					t.Errorf("%s() error = %v with limit %d, want wrapping encoding.ErrSizeLimit", op, opErr, tt.limit)
				}
				if !errors.Is(opErr, ErrContentEncoding) {
					t.Errorf("%s() error = %v with limit %d, want wrapping ErrContentEncoding", op, opErr, tt.limit)
				}
			}
			if content != nil {
				t.Errorf("Content() = %d bytes with the error, want none", len(content))
			}
			if got := m.ContentOrRaw(); !bytes.Equal(got, m.RawContent) {
				t.Errorf("ContentOrRaw() = %d bytes with limit %d, want the %d-byte raw body", len(got), tt.limit, len(m.RawContent))
			}
			// TextOrRaw decodes the raw bytes in the inferred character
			// set, Latin-1 here, as for any other undecodable body.
			if got, want := m.TextOrRaw(), latin1(m.RawContent); got != want {
				t.Errorf("TextOrRaw() = %d characters with limit %d, want the %d-character Latin-1 text of the raw body", len(got), tt.limit, len(want))
			}
		})
	}
}

// heapAllocBytes returns the cumulative bytes allocated on the heap, from
// runtime/metrics.
func heapAllocBytes(t *testing.T) uint64 {
	t.Helper()
	sample := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		t.Fatalf("metric %s has kind %v, want Uint64", sample[0].Name, sample[0].Value.Kind())
	}
	return sample[0].Value.Uint64()
}

// TestDecodeLimitHeapGrowth checks that refusing a body over the limit
// costs allocations bounded by the limit, not by the decoded size: a gzip
// body that decodes to 2 MiB, refused at a 1 MiB limit, allocates below
// 8 MiB plus the decoder's fixed buffers. The 8 MiB covers the decoder's
// output buffer, documented at up to 4 times the limit and doubled under
// the race detector; the allowance on top covers the 32 KiB flate window
// and the error values. The test reads process-global allocation counters,
// so it must not run in parallel.
func TestDecodeLimitHeapGrowth(t *testing.T) {
	const (
		limit = 1 << 20
		bound = 8<<20 + 512<<10
	)
	setDecodeLimit(t, limit)
	m := gzipMessage(t, 2<<20)
	// Warm up lazily initialised state before measuring.
	if _, err := m.Content(); !errors.Is(err, netencoding.ErrSizeLimit) {
		t.Fatalf("Content() error = %v, want wrapping encoding.ErrSizeLimit", err)
	}

	runtime.GC()
	before := heapAllocBytes(t)
	got := m.ContentOrRaw()
	grew := heapAllocBytes(t) - before

	if !bytes.Equal(got, m.RawContent) {
		t.Fatalf("ContentOrRaw() = %d bytes, want the %d-byte raw body", len(got), len(m.RawContent))
	}
	t.Logf("ContentOrRaw allocated %d bytes with limit %d (bound %d)", grew, limit, bound)
	if grew > bound {
		t.Errorf("ContentOrRaw allocated %d bytes with limit %d, want at most %d", grew, limit, bound)
	}
}
