// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package encoding

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	rand "math/rand/v2"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func TestIdentity(t *testing.T) {
	for _, enc := range []string{"identity", "none", "IDENTITY"} {
		t.Run(enc, func(t *testing.T) {
			in := []byte("string")
			got, err := Decode(in, enc)
			if err != nil {
				t.Fatalf("Decode(%q, %q) error: %v", in, enc, err)
			}
			if diff := cmp.Diff(in, got); diff != "" {
				t.Errorf("Decode(%q, %q) mismatch (-want +got):\n%s", in, enc, diff)
			}
			got, err = Encode(in, enc)
			if err != nil {
				t.Fatalf("Encode(%q, %q) error: %v", in, enc, err)
			}
			if diff := cmp.Diff(in, got); diff != "" {
				t.Errorf("Encode(%q, %q) mismatch (-want +got):\n%s", in, enc, diff)
			}
		})
	}
}

func TestUnknownEncoding(t *testing.T) {
	tests := map[string]struct {
		encoding string
		call     func([]byte, string) ([]byte, error)
		wantOp   string
	}{
		"error: encode nonexistent encoding":   {encoding: "nonexistent encoding", call: Encode, wantOp: "encoding"},
		"error: decode nonexistent encoding":   {encoding: "nonexistent encoding", call: Decode, wantOp: "decoding"},
		"error: text codecs are not supported": {encoding: "utf8", call: Decode, wantOp: "decoding"},
		"error: latin-1 is not supported":      {encoding: "latin-1", call: Encode, wantOp: "encoding"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tt.call([]byte("string"), tt.encoding)
			if !errors.Is(err, ErrUnknownEncoding) {
				t.Fatalf("error = %v, want wrapping ErrUnknownEncoding", err)
			}
			e, ok := errors.AsType[*Error](err)
			if !ok {
				t.Fatalf("error %T is not *Error", err)
			}
			want := &Error{Op: tt.wantOp, Encoding: tt.encoding, Prefix: []byte("string"), Err: ErrUnknownEncoding}
			if diff := cmp.Diff(*want, *e, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("error mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEncoders(t *testing.T) {
	for _, enc := range []string{"gzip", "GZIP", "br", "deflate", "deflateraw", "zstd"} {
		t.Run(enc, func(t *testing.T) {
			got, err := Decode(nil, enc)
			if err != nil {
				t.Fatalf("Decode(empty) error: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("Decode(empty) = %q, want empty", got)
			}

			encoded, err := Encode([]byte("string"), enc)
			if err != nil {
				t.Fatalf("Encode error: %v", err)
			}
			got, err = Decode(encoded, enc)
			if err != nil {
				t.Fatalf("Decode(Encode(%q)) error: %v", "string", err)
			}
			if diff := cmp.Diff([]byte("string"), got); diff != "" {
				t.Errorf("round trip mismatch (-want +got):\n%s", diff)
			}

			encodedEmpty, err := Encode(nil, enc)
			if err != nil {
				t.Fatalf("Encode(empty) error: %v", err)
			}
			if len(encodedEmpty) == 0 {
				t.Errorf("Encode(empty) produced no bytes, want a valid empty %s stream", enc)
			}

			if _, err := Decode([]byte("foobar"), enc); err == nil {
				t.Errorf("Decode(%q) succeeded, want error", "foobar")
			}
		})
	}
}

func TestEncodings(t *testing.T) {
	got := Encodings()
	want := []string{"none", "identity", "gzip", "deflate", "deflateraw", "br", "zstd"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Encodings() mismatch (-want +got):\n%s", diff)
	}
	got[0] = "mutated"
	if Encodings()[0] != "none" {
		t.Error("Encodings() exposes the package's slice")
	}
}

// The vectors below were produced by CPython 3.14 (gzip, zlib,
// compression.zstd) and the brotli package, and the expectations by running
// mitmproxy's encoding.decode on the same input.
func TestDecodeVectors(t *testing.T) {
	gzipMitmproxy := "1f8b0800e4a4106902ffcbcd2cc92d28caafa80400d21f9c9d09000000"
	gzipZeroMtime := "1f8b08000000000002ffcbcd2cc92d28caafa80400d21f9c9d09000000"
	gzipSecond := "1f8b08000000000002ff2b4e4dcecf4b010069111fb606000000"
	tests := map[string]struct {
		encoding string
		input    string
		want     string
		wantErr  bool
	}{
		"success: regular gzip": {
			encoding: "gzip", input: gzipMitmproxy, want: "mitmproxy",
		},
		"success: gzip decoder accepts zlib": {
			encoding: "gzip", input: "789ccbcd2cc92d28caafa80400138e03fa", want: "mitmproxy",
		},
		// https://github.com/mitmproxy/mitmproxy/issues/7795
		"success: truncated gzip yields the decoded prefix": {
			encoding: "gzip",
			input: "1f8b08000000000000ffaa564a2d2a72ce4f4955b2d235d551502a4a2df12d4e57" +
				"b2527ab17efbb38d4d4f7b5a9fec58fb6cd3c267733a934a3353946a01000000ffff",
			want: "{\"errCode\":-5, \"retMsg\":\"\xe8\xaf\xb7\xe6\xb1\x82\xe5\x8c\x85\xe4" +
				"\xb8\xad\xe6\xb2\xa1\xe6\x9c\x89buid\"}",
		},
		"success: gzip without trailer": {
			encoding: "gzip", input: gzipZeroMtime[:len(gzipZeroMtime)-16], want: "mitmproxy",
		},
		"success: gzip with half a header": {
			encoding: "gzip", input: gzipZeroMtime[:10], want: "",
		},
		"success: gzip single byte 0x1f": {encoding: "gzip", input: "1f", want: ""},
		"success: gzip single byte 'x'":  {encoding: "gzip", input: "78", want: ""},
		"success: gzip single byte 'a'":  {encoding: "gzip", input: "61", want: ""},
		"success: gzip decodes only the first member": {
			encoding: "gzip", input: gzipZeroMtime + gzipSecond, want: "mitmproxy",
		},
		"success: gzip ignores trailing garbage": {
			encoding: "gzip", input: gzipZeroMtime + hex.EncodeToString([]byte("garbage")), want: "mitmproxy",
		},
		"error: gzip with a bad crc": {
			encoding: "gzip", input: gzipZeroMtime[:len(gzipZeroMtime)-12] + "00" + gzipZeroMtime[len(gzipZeroMtime)-10:],
			wantErr: true,
		},
		"success: deflate zlib-wrapped": {
			encoding: "deflate", input: "789ccbcd2cc92d28caafa80400138e03fa", want: "mitmproxy",
		},
		"success: deflate raw": {
			encoding: "deflate", input: "cbcd2cc92d28caafa80400", want: "mitmproxy",
		},
		"success: deflateraw raw": {
			encoding: "deflateraw", input: "cbcd2cc92d28caafa80400", want: "mitmproxy",
		},
		"success: deflate ignores trailing data": {
			encoding: "deflate", input: "789ccbcd2cc92d28caafa80400138e03fa" + hex.EncodeToString([]byte("junk")), want: "mitmproxy",
		},
		"error: deflate truncated": {
			encoding: "deflate", input: "789ccbcd2cc92d28caafa804", wantErr: true,
		},
		"error: deflate missing checksum": {
			encoding: "deflate", input: "789ccbcd2cc92d28caafa80400", wantErr: true,
		},
		"success: brotli": {
			encoding: "br", input: "0b04806d69746d70726f787903", want: "mitmproxy",
		},
		"error: brotli with trailing data": {
			encoding: "br", input: "0b04806d69746d70726f787903" + "7878", wantErr: true,
		},
		"error: brotli truncated": {
			encoding: "br", input: "0b04806d69746d70726f78", wantErr: true,
		},
		"success: zstd": {
			encoding: "zstd", input: "28b52ffd20094900006d69746d70726f7879", want: "mitmproxy",
		},
		"success: zstd after a skippable frame": {
			encoding: "zstd", input: "502a4d1803000000aabbcc" + "28b52ffd20094900006d69746d70726f7879", want: "mitmproxy",
		},
		"error: zstd with trailing data": {
			encoding: "zstd", input: "28b52ffd20094900006d69746d70726f7879" + hex.EncodeToString([]byte("junk")), wantErr: true,
		},
		"error: zstd truncated": {
			encoding: "zstd", input: "28b52ffd20094900006d69746d70", wantErr: true,
		},
		"success: encoding name is case-insensitive": {
			encoding: "GZip", input: gzipMitmproxy, want: "mitmproxy",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			in := mustHex(t, tt.input)
			got, err := Decode(in, tt.encoding)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Decode(%x, %q) = %q, want error", in, tt.encoding, got)
				}
				e, ok := errors.AsType[*Error](err)
				if !ok || e.Op != "decoding" {
					t.Errorf("Decode error = %#v, want *Error with Op decoding", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode(%x, %q) error: %v", in, tt.encoding, err)
			}
			if diff := cmp.Diff(tt.want, string(got)); diff != "" {
				t.Errorf("Decode(%x, %q) mismatch (-want +got):\n%s", in, tt.encoding, diff)
			}
		})
	}
}

// TestEncodeFraming checks the stream framing upstream's encoders produce:
// a gzip header with a zero mtime and an unknown OS, and a zlib header that
// declares the fastest compression level. The compressed blocks themselves
// depend on the compressor implementation and are only checked by round trip.
func TestEncodeFraming(t *testing.T) {
	tests := map[string]struct {
		encoding  string
		check     func([]byte) []byte
		wantFrame string
	}{
		"success: gzip header has zero mtime and OS 255": {
			encoding: "gzip",
			// Magic, CM, FLG, MTIME; XFL is informational and skipped; OS.
			check:     func(b []byte) []byte { return append(b[:8:8], b[9]) },
			wantFrame: "1f8b080000000000ff",
		},
		"success: deflate is zlib-wrapped at the fastest level": {
			encoding:  "deflate",
			check:     func(b []byte) []byte { return b[:2] },
			wantFrame: "7801",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Encode([]byte("mitmproxy"), tt.encoding)
			if err != nil {
				t.Fatalf("Encode error: %v", err)
			}
			if diff := cmp.Diff(tt.wantFrame, hex.EncodeToString(tt.check(got))); diff != "" {
				t.Errorf("Encode(%q) = %x, framing mismatch (-want +got):\n%s", tt.encoding, got, diff)
			}
		})
	}
}

func TestZstdFrames(t *testing.T) {
	const frameSize = 1024
	payload := bytes.Repeat([]byte("a"), frameSize)
	single, err := Encode(payload, "zstd")
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	got, err := Decode(single, "zstd")
	if err != nil {
		t.Fatalf("Decode(single frame) error: %v", err)
	}
	if len(got) != frameSize {
		t.Errorf("len(Decode(single frame)) = %d, want %d", len(got), frameSize)
	}
	got, err = Decode(append(bytes.Clone(single), single...), "zstd")
	if err != nil {
		t.Fatalf("Decode(two frames) error: %v", err)
	}
	if len(got) != 2*frameSize {
		t.Errorf("len(Decode(two frames)) = %d, want %d", len(got), 2*frameSize)
	}
}

func TestRoundTripLarge(t *testing.T) {
	payload := benchPayload(256 << 10)
	for _, enc := range []string{"gzip", "deflate", "br", "zstd"} {
		t.Run(enc, func(t *testing.T) {
			encoded, err := Encode(payload, enc)
			if err != nil {
				t.Fatalf("Encode error: %v", err)
			}
			got, err := Decode(encoded, enc)
			if err != nil {
				t.Fatalf("Decode error: %v", err)
			}
			if !bytes.Equal(payload, got) {
				t.Errorf("round trip of %d bytes changed the payload (got %d bytes)", len(payload), len(got))
			}
		})
	}
}

// benchPayload returns n bytes of loosely structured text that compresses
// roughly like an HTML or JSON body.
func benchPayload(n int) []byte {
	words := []string{"mitmproxy", "flow", "request", "response", "header", "content", "{", "}", "\"key\":", "1234", "\n"}
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // A fixed seed keeps the benchmark payload reproducible.
	var buf bytes.Buffer
	for buf.Len() < n {
		fmt.Fprintf(&buf, "%s ", words[r.IntN(len(words))])
	}
	return buf.Bytes()[:n]
}

func BenchmarkDecodeGzip1MiB(b *testing.B) {
	payload := benchPayload(1 << 20)
	encoded, err := Encode(payload, "gzip")
	if err != nil {
		b.Fatalf("Encode error: %v", err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(encoded, "gzip"); err != nil {
			b.Fatalf("Decode error: %v", err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	payload := []byte("mitmproxy fuzz seed payload")
	for _, enc := range Encodings() {
		encoded, err := Encode(payload, enc)
		if err != nil {
			f.Fatalf("Encode(%q) error: %v", enc, err)
		}
		f.Add(encoded, enc)
	}
	f.Fuzz(func(t *testing.T, data []byte, enc string) {
		out, err := Decode(data, enc)
		if err != nil {
			return
		}
		// Whatever decodes must survive an encode and decode round trip.
		re, err := Encode(out, enc)
		if err != nil {
			t.Fatalf("Encode(Decode(%x)) error: %v", data, err)
		}
		back, err := Decode(re, enc)
		if err != nil {
			t.Fatalf("Decode(Encode(Decode(%x))) error: %v", data, err)
		}
		if !bytes.Equal(out, back) {
			t.Fatalf("round trip changed %d bytes into %d bytes", len(out), len(back))
		}
	})
}

func TestGzipSizeHint(t *testing.T) {
	valid, err := Encode(bytes.Repeat([]byte("a"), 5000), "gzip")
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	forged := bytes.Clone(valid)
	copy(forged[len(forged)-4:], []byte{0xff, 0xff, 0xff, 0x7f})
	tests := map[string]struct {
		data []byte
		want int
	}{
		"success: trusts the ISIZE trailer": {data: valid, want: 5000},
		"success: forged ISIZE falls back to a guess": {
			data: forged, want: len(forged) * expansionGuess,
		},
		"success: zlib data uses a guess": {
			data: mustHex(t, "789ccbcd2cc92d28caafa80400138e03fa"), want: 17 * expansionGuess,
		},
		"success: short input uses a guess": {data: []byte{0x1f, 0x8b}, want: 2 * expansionGuess},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := gzipSizeHint(tt.data); got != tt.want {
				t.Errorf("gzipSizeHint() = %d, want %d", got, tt.want)
			}
		})
	}
}
