// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// TestParseICO ports upstream's test_ico table for mitmproxy/data/image.ico.
func TestParseICO(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fixture string
		want    [][2]string
		wantErr bool
	}{
		"success: three bitmap images": {
			fixture: "mitmproxy/image.ico",
			want: [][2]string{
				{"Format", "ICO"},
				{"Number of images", "3"},
				{"Image 1", "Size: 48 x 48\n                  Bits per pixel: 24\n                  PNG: False"},
				{"Image 2", "Size: 32 x 32\n                  Bits per pixel: 24\n                  PNG: False"},
				{"Image 3", "Size: 16 x 16\n                  Bits per pixel: 24\n                  PNG: False"},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseICO(testutil.Fixture(t, tt.fixture))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %t", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

// icoDirectory frames one directory entry pointing at the given offset,
// followed by the rest of the file's bytes.
func icoDirectory(offset uint32, rest []byte) []byte {
	out := []byte{0, 0, 1, 0, 1, 0} // magic, one image
	out = append(out, 0, 0, 0, 0)   // 256 x 256, no palette, reserved
	out = append(out, 1, 0, 32, 0)  // planes, bits per pixel
	out = append(out, 22, 0, 0, 0)  // data length
	out = binary.LittleEndian.AppendUint32(out, offset)
	return append(out, rest...)
}

// TestParseICOMalformed exercises the directory error paths.
func TestParseICOMalformed(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		data []byte
		want [][2]string
	}{
		"error: wrong magic": {
			data: []byte{0, 0, 2, 0, 1, 0},
		},
		"error: reserved byte set": {
			data: []byte{0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 32, 0, 22, 0, 0, 0, 22, 0, 0, 0},
		},
		"error: directory cut short": {
			data: []byte{0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 1, 0},
		},
		"error: image offset past the end": {
			data: icoDirectory(1<<30, nil),
		},
		"success: zero dimensions mean 256 and PNG data is reported": {
			data: icoDirectory(22, append([]byte{}, pngMagic...)),
			want: [][2]string{
				{"Format", "ICO"},
				{"Number of images", "1"},
				{"Image 1", "Size: 256 x 256\n                  Bits per pixel: 32\n                  PNG: True"},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseICO(tt.data)
			if (err != nil) != (tt.want == nil) {
				t.Fatalf("ParseICO() = %v, error = %v; want error %t", got, err, tt.want == nil)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

// TestParseICOTruncated feeds the parser every prefix of a fixture: no
// prefix may panic, and a prefix may parse only once it holds the whole
// directory and every image's PNG probe window.
func TestParseICOTruncated(t *testing.T) {
	t.Parallel()
	data := testutil.Fixture(t, "mitmproxy/image.ico")
	for i := range len(data) {
		_, err := ParseICO(data[:i])
		if (err == nil) != icoPrefixParses(data, i) {
			t.Fatalf("ParseICO(data[:%d]) error = %v; want the opposite", i, err)
		}
	}
}

// icoPrefixParses reports whether the first i bytes of a well-formed ICO
// file hold its directory and the 8 probed bytes of every image.
func icoPrefixParses(data []byte, i int) bool {
	numImages := int(binary.LittleEndian.Uint16(data[4:]))
	if i < 6+16*numImages {
		return false
	}
	for img := range numImages {
		offset := binary.LittleEndian.Uint32(data[6+16*img+12:])
		if int64(offset)+8 > int64(i) {
			return false
		}
	}
	return true
}
