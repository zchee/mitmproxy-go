// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package encoding

import (
	"bytes"
	"errors"
	"math"
	"runtime"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/google/go-cmp/cmp"
	"github.com/klauspost/compress/zstd"
)

const (
	bombSize  = 64 << 20
	bombLimit = 1 << 20
)

// bomb returns bombSize zero bytes encoded with enc, a body a few KiB long
// that decodes to 64 MiB.
func bomb(t testing.TB, enc string) []byte {
	t.Helper()
	encoded, err := Encode(make([]byte, bombSize), enc)
	if err != nil {
		t.Fatalf("Encode(%q) error: %v", enc, err)
	}
	return encoded
}

// zstdStream encodes data as a zstd frame that does not declare its
// content size, as a streaming compressor writes it, so that a decoder
// cannot refuse it from the frame header.
func zstdStream(t testing.TB, data []byte, opts ...zstd.EOption) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, append([]zstd.EOption{zstd.WithEncoderLevel(zstd.SpeedFastest)}, opts...)...)
	if err != nil {
		t.Fatalf("zstd.NewWriter error: %v", err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zstd write error: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close error: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeLimitStopsAtLimit(t *testing.T) {
	tests := map[string]struct {
		data     []byte
		encoding string
	}{
		"error: identity":   {data: make([]byte, bombLimit+1), encoding: "identity"},
		"error: none":       {data: make([]byte, bombLimit+1), encoding: "none"},
		"error: gzip":       {data: bomb(t, "gzip"), encoding: "gzip"},
		"error: deflate":    {data: bomb(t, "deflate"), encoding: "deflate"},
		"error: deflateraw": {data: bomb(t, "deflateraw"), encoding: "deflateraw"},
		"error: raw deflate without the zlib wrapper": {
			data: bomb(t, "deflate")[2:], encoding: "deflate",
		},
		"error: brotli": {data: bomb(t, "br"), encoding: "br"},
		"error: zstd with the content size in the frame header": {
			data: bomb(t, "zstd"), encoding: "zstd",
		},
		"error: zstd stream without a content size": {
			data: zstdStream(t, make([]byte, bombSize)), encoding: "zstd",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeLimit(tt.data, tt.encoding, bombLimit)
			if !errors.Is(err, ErrSizeLimit) {
				t.Fatalf("DecodeLimit(%d bytes, %q, %d) error = %v, want wrapping ErrSizeLimit", len(tt.data), tt.encoding, bombLimit, err)
			}
			if got != nil {
				t.Errorf("DecodeLimit returned %d bytes with the error, want none", len(got))
			}
			e, ok := errors.AsType[*Error](err)
			if !ok || e.Op != "decoding" {
				t.Errorf("DecodeLimit error = %#v, want *Error with Op decoding", err)
			}
		})
	}
}

// TestDecodeLimitBoundary checks that the limit is inclusive: output of
// exactly limit bytes decodes, one byte more does not.
func TestDecodeLimitBoundary(t *testing.T) {
	payload := benchPayload(64 << 10)
	for _, enc := range Encodings() {
		t.Run(enc, func(t *testing.T) {
			encoded, err := Encode(payload, enc)
			if err != nil {
				t.Fatalf("Encode error: %v", err)
			}
			n := int64(len(payload))
			got, err := DecodeLimit(encoded, enc, n)
			if err != nil {
				t.Fatalf("DecodeLimit(limit %d) error: %v", n, err)
			}
			if !bytes.Equal(payload, got) {
				t.Errorf("DecodeLimit(limit %d) = %d bytes, want the %d-byte payload", n, len(got), len(payload))
			}
			if _, err := DecodeLimit(encoded, enc, n-1); !errors.Is(err, ErrSizeLimit) {
				t.Errorf("DecodeLimit(limit %d) error = %v, want wrapping ErrSizeLimit", n-1, err)
			}
			got, err = DecodeLimit(encoded, enc, math.MaxInt64)
			if err != nil || !bytes.Equal(payload, got) {
				t.Errorf("DecodeLimit(limit MaxInt64) = %d bytes, %v; want the %d-byte payload", len(got), err, len(payload))
			}
		})
	}
}

// TestDecodeLimitMatchesDecode checks that under the limit DecodeLimit
// returns what Decode returns, including the tolerated truncated gzip
// stream and the errors of invalid input.
func TestDecodeLimitMatchesDecode(t *testing.T) {
	gzipBody, err := Encode(benchPayload(32<<10), "gzip")
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	tests := map[string]struct {
		data     []byte
		encoding string
	}{
		"success: gzip":                    {data: gzipBody, encoding: "gzip"},
		"success: truncated gzip":          {data: gzipBody[:len(gzipBody)/2], encoding: "gzip"},
		"success: gzip with half a header": {data: gzipBody[:5], encoding: "gzip"},
		"success: zlib in gzip":            {data: mustHex(t, "789ccbcd2cc92d28caafa80400138e03fa"), encoding: "gzip"},
		"success: raw deflate":             {data: mustHex(t, "cbcd2cc92d28caafa80400"), encoding: "deflate"},
		"success: brotli":                  {data: mustHex(t, "0b04806d69746d70726f787903"), encoding: "br"},
		"success: zstd stream":             {data: zstdStream(t, []byte("mitmproxy")), encoding: "zstd"},
		"success: empty zstd":              {data: nil, encoding: "zstd"},
		"success: identity":                {data: []byte("mitmproxy"), encoding: "identity"},
		"error: deflate truncated":         {data: mustHex(t, "789ccbcd2cc92d28caafa804"), encoding: "deflate"},
		"error: brotli with trailing data": {
			data: mustHex(t, "0b04806d69746d70726f7879037878"), encoding: "br",
		},
		"error: zstd truncated":   {data: mustHex(t, "28b52ffd20094900006d69746d70"), encoding: "zstd"},
		"error: unknown encoding": {data: []byte("mitmproxy"), encoding: "utf8"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			want, wantErr := Decode(tt.data, tt.encoding)
			got, err := DecodeLimit(tt.data, tt.encoding, bombLimit)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("DecodeLimit output differs from Decode (-Decode +DecodeLimit):\n%s", diff)
			}
			if (wantErr == nil) != (err == nil) || (err != nil && err.Error() != wantErr.Error()) {
				t.Errorf("DecodeLimit error = %v, Decode error = %v", err, wantErr)
			}
		})
	}
}

// raceEnabled reports whether the test binary was built with the race
// detector, which changes how much some code allocates.
var raceEnabled bool

// brotliBomb returns bombSize zero bytes encoded with brotli's largest
// window, 2^24, which sets the size of the decoder's ring buffer.
func brotliBomb(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	bw := brotli.NewWriterOptions(&buf, brotli.WriterOptions{Quality: 0, LGWin: 24})
	if _, err := bw.Write(make([]byte, bombSize)); err != nil {
		t.Fatalf("brotli write error: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close error: %v", err)
	}
	return buf.Bytes()
}

// TestDecodeLimitAllocations checks that a bomb of each coding is refused
// with allocations within the bounds DecodeLimit documents, far below the
// 64 MiB that Decode allocates. Each input uses the largest window
// DecodeLimit accepts at that limit, the worst case for the decoder.
func TestDecodeLimitAllocations(t *testing.T) {
	const small = 1 << 10
	deflateBomb := bomb(t, "deflate")
	brBomb := brotliBomb(t)
	// No content size in the frame header: a frame that declares one
	// larger than the limit is refused before decoding.
	zstdBomb := zstdStream(t, make([]byte, bombSize), zstd.WithWindowSize(8<<20))
	// The race detector's instrumentation keeps the compiler from turning
	// the append of a fresh slice in bytes.Buffer's growth into a single
	// allocation, which doubles what the output buffer allocates.
	growth := int64(1)
	if raceEnabled {
		growth = 2
	}
	outputBound := func(limit int64) int64 { return growth*4*limit + 64<<10 }
	brotliBound := func(limit int64) int64 { return 36<<20 + growth*3*limit }
	zstdBound := func(limit int64) int64 { return 7 * max(limit, 8<<20) }
	tests := map[string]struct {
		data     []byte
		encoding string
		limit    int64
		bound    func(limit int64) int64
	}{
		"error: gzip":        {data: bomb(t, "gzip"), encoding: "gzip", limit: bombLimit, bound: outputBound},
		"error: deflate":     {data: deflateBomb, encoding: "deflate", limit: bombLimit, bound: outputBound},
		"error: raw deflate": {data: deflateBomb[2:], encoding: "deflate", limit: bombLimit, bound: outputBound},
		// Just above a power of two, the output buffer has doubled past
		// the limit: the worst ratio for gzip and deflate.
		"error: deflate with the limit just above 8 MiB": {
			data: deflateBomb, encoding: "deflate", limit: 9 << 20, bound: outputBound,
		},
		"error: brotli with a small limit": {data: brBomb, encoding: "br", limit: small, bound: brotliBound},
		"error: brotli":                    {data: brBomb, encoding: "br", limit: bombLimit, bound: brotliBound},
		"error: brotli with a 16 MiB limit": {
			data: brBomb, encoding: "br", limit: 16 << 20, bound: brotliBound,
		},
		"error: zstd with a small limit": {data: zstdBomb, encoding: "zstd", limit: small, bound: zstdBound},
		"error: zstd with a 16 MiB limit": {
			data: zstdBomb, encoding: "zstd", limit: 16 << 20, bound: zstdBound,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Warm up lazily initialised state before measuring.
			if _, err := DecodeLimit(tt.data, tt.encoding, tt.limit); !errors.Is(err, ErrSizeLimit) {
				t.Fatalf("DecodeLimit error = %v, want wrapping ErrSizeLimit", err)
			}
			const runs = 4
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for range runs {
				_, _ = DecodeLimit(tt.data, tt.encoding, tt.limit)
			}
			runtime.ReadMemStats(&after)
			perRun := (after.TotalAlloc - before.TotalAlloc) / runs
			maxPerRun := uint64(tt.bound(tt.limit))
			t.Logf("DecodeLimit(%q) allocated %d bytes per run for a %d-byte bomb with limit %d (bound %d)", tt.encoding, perRun, bombSize, tt.limit, maxPerRun)
			if perRun > maxPerRun {
				t.Errorf("DecodeLimit(%q) allocated %d bytes per run with limit %d, want at most %d", tt.encoding, perRun, tt.limit, maxPerRun)
			}
		})
	}
}

// TestDecodeLimitZstdWindowFloor checks the 8 MiB floor of the zstd bound:
// a frame whose declared window lies above the limit but within 8 MiB, the
// window RFC 9659 lets HTTP senders use, decodes when its content fits the
// limit, and a frame whose window is above 8 MiB and above the limit is
// refused. The frames carry no content size, so only the window can decide.
func TestDecodeLimitZstdWindowFloor(t *testing.T) {
	tests := map[string]struct {
		window  int
		size    int
		limit   int64
		refused bool
	}{
		"success: 1 MiB window under a 768 KiB limit": {window: 1 << 20, size: 512 << 10, limit: 768 << 10},
		"success: 8 MiB window under a 4 MiB limit":   {window: 8 << 20, size: 2 << 20, limit: 4 << 20},
		"error: 16 MiB window under a 4 MiB limit":    {window: 16 << 20, size: 2 << 20, limit: 4 << 20, refused: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			content := bytes.Repeat([]byte("mitmproxy zstd window floor "), tt.size/28+1)[:tt.size]
			data := zstdStream(t, content, zstd.WithWindowSize(tt.window))
			var h zstd.Header
			if err := h.Decode(data); err != nil {
				t.Fatalf("frame header: %v", err)
			}
			if h.HasFCS || h.SingleSegment || h.WindowSize != uint64(tt.window) {
				t.Fatalf("frame header declares window %d (content size %v, single segment %v); want window %d without a content size", h.WindowSize, h.HasFCS, h.SingleSegment, tt.window)
			}

			got, err := DecodeLimit(data, "zstd", tt.limit)
			if tt.refused {
				if got != nil || !errors.Is(err, ErrSizeLimit) || !errors.Is(err, zstd.ErrWindowSizeExceeded) {
					t.Errorf("DecodeLimit(limit %d) = %d bytes, %v; want no output and an error wrapping ErrSizeLimit and zstd.ErrWindowSizeExceeded", tt.limit, len(got), err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeLimit(limit %d) error: %v", tt.limit, err)
			}
			if !bytes.Equal(got, content) {
				t.Errorf("DecodeLimit(limit %d) returned %d bytes that differ from the %d bytes encoded", tt.limit, len(got), len(content))
			}
		})
	}
}

// zstdWideWindow is a zstd frame of 27 bytes whose header declares a 32 MiB
// window without the single-segment flag: Decode accepts it, while
// DecodeLimit refuses it for any limit below 32 MiB because the bound for
// zstd is max(limit, 8 MiB).
const zstdWideWindow = "28b52ffd0478d900006d69746d70726f78792066757a7a2073656564207061796c6f61641077c1db"

// TestDecodeLimitZstdWindow checks that a zstd frame is refused when its
// declared window exceeds the bound DecodeLimit derives from the limit,
// however small its content, and decoded once the bound covers it.
func TestDecodeLimitZstdWindow(t *testing.T) {
	data := mustHex(t, zstdWideWindow)
	want, err := Decode(data, "zstd")
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if diff := cmp.Diff([]byte("mitmproxy fuzz seed payload"), want); diff != "" {
		t.Fatalf("Decode output differs (-want +got):\n%s", diff)
	}
	tests := map[string]struct {
		limit   int64
		wantErr string
	}{
		"error: limit equal to the content size": {
			limit:   int64(len(want)),
			wantErr: "ZstdError when decoding b'(\\xb5/\\x with 'zstd': ZstdError('frame window exceeds the bound of 8388608 bytes for a limit of 27 bytes')",
		},
		"error: limit of 8 MiB": {
			limit:   8 << 20,
			wantErr: "ZstdError when decoding b'(\\xb5/\\x with 'zstd': ZstdError('frame window exceeds the bound of 8388608 bytes for a limit of 8388608 bytes')",
		},
		"success: limit covering the 32 MiB window": {
			limit: 32 << 20,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeLimit(data, "zstd", tt.limit)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("DecodeLimit(limit %d) error: %v", tt.limit, err)
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("DecodeLimit(limit %d) output differs from Decode (-Decode +DecodeLimit):\n%s", tt.limit, diff)
				}
				return
			}
			if got != nil {
				t.Errorf("DecodeLimit(limit %d) returned %d bytes with the error, want none", tt.limit, len(got))
			}
			if !errors.Is(err, ErrSizeLimit) || !errors.Is(err, zstd.ErrWindowSizeExceeded) {
				t.Errorf("DecodeLimit(limit %d) error = %v, want wrapping ErrSizeLimit and zstd.ErrWindowSizeExceeded", tt.limit, err)
			}
			if err != nil {
				if diff := cmp.Diff(tt.wantErr, err.Error()); diff != "" {
					t.Errorf("DecodeLimit(limit %d) error text differs (-want +got):\n%s", tt.limit, diff)
				}
			}
		})
	}
}

// FuzzDecodeLimit checks DecodeLimit against Decode: below the limit both
// agree, above it DecodeLimit fails with ErrSizeLimit. A zstd frame whose
// declared window exceeds the bound DecodeLimit uses may also be refused
// below the limit, with an error that wraps the zstd window error as well.
func FuzzDecodeLimit(f *testing.F) {
	payload := []byte("mitmproxy fuzz seed payload")
	for _, enc := range Encodings() {
		encoded, err := Encode(payload, enc)
		if err != nil {
			f.Fatalf("Encode(%q) error: %v", enc, err)
		}
		f.Add(encoded, enc, int64(len(payload)))
		f.Add(encoded, enc, int64(len(payload)-1))
	}
	// zstd frames declaring a 32 MiB window, refused below that limit.
	for _, seed := range []struct {
		hex   string
		limit int64
	}{
		{hex: zstdWideWindow, limit: 27},
		{hex: "28b52ffd1078310000303030303030", limit: 10},
		{hex: "28b52ffd0078010000", limit: -155},
	} {
		f.Add(mustHex(f, seed.hex), "Zstd", seed.limit)
	}
	f.Fuzz(func(t *testing.T, data []byte, enc string, limit int64) {
		want, wantErr := Decode(data, enc)
		got, err := DecodeLimit(data, enc, limit)
		switch {
		case wantErr != nil:
			// A decoder may stop at the limit before it reaches the corrupt
			// part of the input.
			if err == nil {
				t.Fatalf("DecodeLimit(%x, %q, %d) succeeded where Decode failed: %v", data, enc, limit, wantErr)
			}
		case int64(len(want)) > max(limit, 0):
			if !errors.Is(err, ErrSizeLimit) {
				t.Fatalf("DecodeLimit(%x, %q, %d) error = %v for %d decoded bytes, want ErrSizeLimit", data, enc, limit, err, len(want))
			}
		case err != nil:
			if strings.EqualFold(enc, "zstd") && errors.Is(err, ErrSizeLimit) && errors.Is(err, zstd.ErrWindowSizeExceeded) {
				return
			}
			t.Fatalf("DecodeLimit(%x, %q, %d) error = %v, Decode gave %d bytes", data, enc, limit, err, len(want))
		case !bytes.Equal(want, got):
			t.Fatalf("DecodeLimit(%x, %q, %d) = %x, Decode = %x", data, enc, limit, got, want)
		}
	})
}
