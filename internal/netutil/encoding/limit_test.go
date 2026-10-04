// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package encoding

import (
	"bytes"
	"errors"
	"math"
	"runtime"
	"testing"

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
func zstdStream(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
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

// TestDecodeLimitAllocations checks that a gzip bomb is refused without
// allocating anything close to its decoded size.
func TestDecodeLimitAllocations(t *testing.T) {
	data := bomb(t, "gzip")
	// Warm up lazily initialised state before measuring.
	if _, err := DecodeLimit(data, "gzip", bombLimit); !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("DecodeLimit error = %v, want wrapping ErrSizeLimit", err)
	}
	const runs = 4
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		_, _ = DecodeLimit(data, "gzip", bombLimit)
	}
	runtime.ReadMemStats(&after)
	perRun := (after.TotalAlloc - before.TotalAlloc) / runs
	// The output buffer may grow to twice the limit; the decoder itself
	// keeps a 32 KiB window. Decode allocates the whole 64 MiB.
	const maxPerRun = 4 * bombLimit
	t.Logf("DecodeLimit allocated %d bytes per run for a %d-byte bomb with limit %d", perRun, bombSize, bombLimit)
	if perRun > maxPerRun {
		t.Errorf("DecodeLimit allocated %d bytes per run, want at most %d", perRun, maxPerRun)
	}
}

// FuzzDecodeLimit checks DecodeLimit against Decode: below the limit both
// agree, above it DecodeLimit fails with ErrSizeLimit.
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
			t.Fatalf("DecodeLimit(%x, %q, %d) error = %v, Decode gave %d bytes", data, enc, limit, err, len(want))
		case !bytes.Equal(want, got):
			t.Fatalf("DecodeLimit(%x, %q, %d) = %x, Decode = %x", data, enc, limit, got, want)
		}
	})
}
