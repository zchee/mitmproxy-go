// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// TestParseGIF ports upstream's test_parse_gif table.
func TestParseGIF(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fixture string
		want    [][2]string
	}{
		"success: comment": {
			fixture: "mitmproxy/image_parser/hopper.gif",
			want: [][2]string{
				{"Format", "Compuserve GIF"},
				{"Version", "GIF89a"},
				{"Size", "128 x 128 px"},
				{"background", "0"},
				{"comment", `b'File written by Adobe Photoshop\xa8 4.0'`},
			},
		},
		"success: background": {
			fixture: "mitmproxy/image_parser/chi.gif",
			want: [][2]string{
				{"Format", "Compuserve GIF"},
				{"Version", "GIF89a"},
				{"Size", "320 x 240 px"},
				{"background", "248"},
				{"comment", "b'Created with GIMP'"},
			},
		},
		"success: color table": {
			fixture: "mitmproxy/image_parser/iss634.gif",
			want: [][2]string{
				{"Format", "Compuserve GIF"},
				{"Version", "GIF89a"},
				{"Size", "245 x 245 px"},
				{"background", "0"},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseGIF(testutil.Fixture(t, tt.fixture))
			if err != nil {
				t.Fatalf("ParseGIF() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

// gifHeader frames a minimal screen descriptor without a color table.
func gifHeader() []byte {
	return []byte("GIF89a\x02\x00\x03\x00\x00\x05\x00")
}

// TestParseGIFMalformed exercises the block and extension error paths.
func TestParseGIFMalformed(t *testing.T) {
	t.Parallel()
	header := [][2]string{
		{"Format", "Compuserve GIF"},
		{"Version", "GIF89a"},
		{"Size", "2 x 3 px"},
		{"background", "5"},
	}
	tests := map[string]struct {
		data []byte
		want [][2]string
	}{
		"error: wrong magic": {
			data: []byte("JIF89a"),
		},
		"error: version is not ASCII": {
			data: []byte("GIF8\xffa\x02\x00\x03\x00\x00\x05\x00\x3b"),
		},
		"error: global color table cut short": {
			data: []byte("GIF89a\x02\x00\x03\x00\x80\x05\x00\x01\x02"),
		},
		"error: unknown block type": {
			data: append(gifHeader(), 0x01),
		},
		"error: unknown extension label": {
			data: append(gifHeader(), 0x21, 0x01, 0x02, 'h', 'i', 0x00, 0x3b),
		},
		"error: unknown extension label with truncated subblocks": {
			data: append(gifHeader(), 0x21, 0x01, 0x05, 'h', 'i'),
		},
		"error: graphic control block size": {
			data: append(gifHeader(), 0x21, 0xf9, 0x05),
		},
		"error: graphic control terminator": {
			data: append(gifHeader(), 0x21, 0xf9, 0x04, 1, 2, 3, 4, 0xff),
		},
		"error: application identifier length": {
			data: append(gifHeader(), 0x21, 0xff, 0x0a),
		},
		"error: application identifier is not ASCII": {
			data: append(gifHeader(), 0x21, 0xff, 0x0b, 'N', 'E', 'T', 'S', 'C', 'A', 'P', 0xc9, '2', '.', '0', 0x00, 0x3b),
		},
		"error: comment subblock cut short": {
			data: append(gifHeader(), 0x21, 0xfe, 0x10, 'h', 'i'),
		},
		"error: image descriptor cut short": {
			data: append(gifHeader(), 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01),
		},
		"success: empty comment subblocks add no rows": {
			data: append(gifHeader(), 0x21, 0xfe, 0x00, 0x3b),
			want: header,
		},
		"success: trailing bytes after the trailer are ignored": {
			data: append(gifHeader(), 0x3b, 'j', 'u', 'n', 'k'),
			want: header,
		},
		"error: no blocks after the header": {
			data: gifHeader(),
		},
		"success: data ending at a block boundary without a trailer": {
			data: append(gifHeader(), 0x21, 0xfe, 0x02, 'h', 'i', 0x00),
			want: append(header, [2]string{"comment", "b'hi'"}),
		},
		"success: comment rows keep file order": {
			data: append(gifHeader(),
				0x21, 0xfe, 0x02, 'h', 'i', 0x00,
				0x21, 0xf9, 0x04, 0, 0, 0, 0, 0x00,
				0x21, 0xfe, 0x03, 'y', 'o', 0xff, 0x00,
				0x3b),
			want: append(header,
				[2]string{"comment", "b'hi'"},
				[2]string{"comment", `b'yo\xff'`},
			),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseGIF(tt.data)
			if (err != nil) != (tt.want == nil) {
				t.Fatalf("ParseGIF() = %v, error = %v; want error %t", got, err, tt.want == nil)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

// TestParseGIFTruncated feeds the parser every prefix of a fixture: no
// prefix may panic, and a cut anywhere up to the end of the fixed header
// must fail, because at least one block has to follow it.
func TestParseGIFTruncated(t *testing.T) {
	t.Parallel()
	data := testutil.Fixture(t, "mitmproxy/image_parser/chi.gif")
	for i := range len(data) {
		if _, err := ParseGIF(data[:i]); err == nil && i <= 13 {
			t.Fatalf("ParseGIF(data[:%d]) succeeded inside the header", i)
		}
	}
}
