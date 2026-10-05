// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// pngSuiteDescription is the text chunk shared by the PngSuite fixtures.
const pngSuiteDescription = "A compilation of a set of images created to test the\n" +
	"various color-types of the PNG format. Included are\nblack&white, color," +
	" paletted, with alpha channel, with\ntransparency formats. All bit-depths" +
	" allowed according\nto the spec are present."

// TestParsePNG ports upstream's test_parse_png table.
func TestParsePNG(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fixture string
		want    [][2]string
	}{
		"success: no textual data": {
			fixture: "mitmproxy/image_parser/ct0n0g04.png",
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "32 x 32 px"},
				{"gamma", "1.0"},
			},
		},
		"success: with textual data": {
			fixture: "mitmproxy/image_parser/ct1n0g04.png",
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "32 x 32 px"},
				{"gamma", "1.0"},
				{"Title", "PngSuite"},
				{"Author", "Willem A.J. van Schaik\n(willem@schaik.com)"},
				{"Copyright", "Copyright Willem van Schaik, Singapore 1995-96"},
				{"Description", pngSuiteDescription},
				{"Software", `Created on a NeXTstation color using "pnmtopng".`},
				{"Disclaimer", "Freeware."},
			},
		},
		"success: with compressed textual data": {
			fixture: "mitmproxy/image_parser/ctzn0g04.png",
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "32 x 32 px"},
				{"gamma", "1.0"},
				{"Title", "PngSuite"},
				{"Author", "Willem A.J. van Schaik\n(willem@schaik.com)"},
				{"Copyright", "Copyright Willem van Schaik, Singapore 1995-96"},
				{"Description", pngSuiteDescription},
				{"Software", `Created on a NeXTstation color using "pnmtopng".`},
				{"Disclaimer", "Freeware."},
			},
		},
		"success: UTF-8 international text, english": {
			fixture: "mitmproxy/image_parser/cten0g04.png",
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "32 x 32 px"},
				{"gamma", "1.0"},
				{"Title", "PngSuite"},
				{"Author", "Willem van Schaik (willem@schaik.com)"},
				{"Copyright", "Copyright Willem van Schaik, Canada 2011"},
				{"Description", "A compilation of a set of images created to test the " +
					"various color-types of the PNG format. Included are black&white, color," +
					" paletted, with alpha channel, with transparency formats. All bit-depths" +
					" allowed according to the spec are present."},
				{"Software", `Created on a NeXTstation color using "pnmtopng".`},
				{"Disclaimer", "Freeware."},
			},
		},
		"success: gamma value": {
			fixture: "mitmproxy/image_parser/g07n0g16.png",
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "32 x 32 px"},
				{"gamma", "0.7"},
			},
		},
		"success: aspect value": {
			fixture: "mitmproxy/image_parser/aspect.png",
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "1280 x 798 px"},
				{"aspect", "72 x 72"},
				{"date:create", "2012-07-11T14:04:52-07:00"},
				{"date:modify", "2012-07-11T14:04:52-07:00"},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePNG(testutil.Fixture(t, tt.fixture))
			if err != nil {
				t.Fatalf("ParsePNG() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

// pngChunk frames body as a chunk of the given type with a zero checksum,
// which the parser does not verify.
func pngChunk(typ string, body []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	out = append(out, typ...)
	out = append(out, body...)
	return append(out, 0, 0, 0, 0)
}

// pngFile frames chunks after the signature and a 32 x 32 greyscale IHDR.
func pngFile(chunks ...[]byte) []byte {
	ihdr := binary.BigEndian.AppendUint32(nil, 32)
	ihdr = binary.BigEndian.AppendUint32(ihdr, 32)
	ihdr = append(ihdr, 4, 0, 0, 0, 0)
	out := append([]byte{}, pngMagic...)
	out = append(out, pngChunk("IHDR", ihdr)...)
	for _, chunk := range chunks {
		out = append(out, chunk...)
	}
	return append(out, pngChunk("IEND", nil)...)
}

// TestParsePNGMalformed exercises the error paths of every chunk parser.
func TestParsePNGMalformed(t *testing.T) {
	t.Parallel()
	deflated := func(s string) []byte {
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	tests := map[string]struct {
		data []byte
		want [][2]string
	}{
		"error: wrong magic": {
			data: []byte("\x89PNG\r\n\x1a_rest"),
		},
		"error: IHDR length is not 13": {
			data: append(append([]byte{}, pngMagic...), 0, 0, 0, 12),
		},
		"error: first chunk is not IHDR": {
			data: append(append([]byte{}, pngMagic...), 0, 0, 0, 13, 'J', 'H', 'D', 'R'),
		},
		"error: chunk type is not UTF-8": {
			data: append(pngFile()[:33:33], pngChunk("t\xffXt", nil)...),
		},
		"error: chunk length past the end": {
			data: append(pngFile()[:33:33], 0, 0, 0, 99, 't', 'E', 'X', 't'),
		},
		"error: tEXt keyword without terminator": {
			data: pngFile(pngChunk("tEXt", []byte("keyword without NUL"))),
		},
		"error: iTXt keyword is not UTF-8": {
			data: pngFile(pngChunk("iTXt", []byte("k\xff\x00\x00\x00en\x00k\x00text"))),
		},
		"error: iTXt language is not ASCII": {
			data: pngFile(pngChunk("iTXt", []byte("k\x00\x00\x00e\xffn\x00k\x00text"))),
		},
		"error: gAMA too short": {
			data: pngFile(pngChunk("gAMA", []byte{0, 1, 134})),
		},
		"error: PLTE with trailing bytes": {
			data: pngFile(pngChunk("PLTE", []byte{1, 2, 3, 4, 5})),
		},
		"error: greyscale bKGD too short": {
			data: pngFile(pngChunk("bKGD", []byte{1})),
		},
		"error: pHYs too short": {
			data: pngFile(pngChunk("pHYs", []byte{0, 0, 0, 72, 0, 0, 0, 72})),
		},
		"error: zTXt with invalid zlib data": {
			data: pngFile(pngChunk("zTXt", []byte("k\x00\x00not zlib"))),
		},
		"error: zTXt with truncated zlib data": {
			data: pngFile(pngChunk("zTXt", append([]byte("k\x00\x00"), deflated("text")[:5]...))),
		},
		"success: zTXt text decoded as latin-1": {
			data: pngFile(pngChunk("zTXt", append([]byte("k\x00\x00"), deflated("caf\xe9")...))),
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "32 x 32 px"},
				{"k", "café"},
			},
		},
		"success: unknown chunk type is skipped": {
			data: pngFile(pngChunk("eXIf", []byte("anything"))),
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "32 x 32 px"},
			},
		},
		"success: chunks after IEND are ignored": {
			data: append(pngFile(), "trailing garbage"...),
			want: [][2]string{
				{"Format", "Portable network graphics"},
				{"Size", "32 x 32 px"},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePNG(tt.data)
			if (err != nil) != (tt.want == nil) {
				t.Fatalf("ParsePNG() = %v, error = %v; want error %t", got, err, tt.want == nil)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

// TestParsePNGTruncated feeds the parser every prefix of a fixture: no
// prefix may panic, and only a cut at a chunk boundary may succeed.
func TestParsePNGTruncated(t *testing.T) {
	t.Parallel()
	data := testutil.Fixture(t, "mitmproxy/image_parser/ct0n0g04.png")
	for i := range len(data) {
		if _, err := ParsePNG(data[:i]); err == nil {
			// The chunk loop also ends at the end of the data, so a cut
			// exactly between chunks parses; a cut inside a chunk must not.
			if !atPNGChunkBoundary(t, data, i) {
				t.Fatalf("ParsePNG(data[:%d]) succeeded inside a chunk", i)
			}
		}
	}
}

// atPNGChunkBoundary reports whether offset i in a well-formed PNG file
// falls exactly between two chunks.
func atPNGChunkBoundary(t *testing.T, data []byte, i int) bool {
	t.Helper()
	pos := len(pngMagic)
	for pos < i {
		length := binary.BigEndian.Uint32(data[pos:])
		pos += 12 + int(length)
	}
	return pos == i
}
