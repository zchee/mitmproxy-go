// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// TestImagePrettify ports upstream's test_view_image: the heading names
// the format of each sample image, in upper case.
func TestImagePrettify(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fixture string
	}{
		"success: png":  {fixture: "mitmproxy/image.png"},
		"success: gif":  {fixture: "mitmproxy/image.gif"},
		"success: jpeg": {fixture: "mitmproxy/all.jpeg"},
		"success: ico":  {fixture: "mitmproxy/image.ico"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			desc, err := (Image{}).Prettify(testutil.Fixture(t, tt.fixture), Metadata{})
			if err != nil {
				t.Fatalf("Prettify() error = %v", err)
			}
			ext := strings.ToUpper(tt.fixture[strings.LastIndexByte(tt.fixture, '.')+1:])
			if !strings.Contains(desc, ext) {
				t.Fatalf("Prettify() = %q, does not contain %q", desc, ext)
			}
		})
	}
	t.Run("success: unknown image", func(t *testing.T) {
		t.Parallel()
		desc, err := (Image{}).Prettify([]byte("flibble"), Metadata{})
		if err != nil {
			t.Fatalf("Prettify() error = %v", err)
		}
		if diff := cmp.Diff("# Unknown Image\n", desc); diff != "" {
			t.Fatalf("text (-want +got):\n%s", diff)
		}
	})
	t.Run("success: detected format without a parser gets the heading alone", func(t *testing.T) {
		t.Parallel()
		desc, err := (Image{}).Prettify([]byte("MM\x00\x2a"), Metadata{})
		if err != nil {
			t.Fatalf("Prettify() error = %v", err)
		}
		if diff := cmp.Diff("# TIFF Image\n", desc); diff != "" {
			t.Fatalf("text (-want +got):\n%s", diff)
		}
	})
}

// TestImageRenderPriority ports upstream's test_render_priority.
func TestImageRenderPriority(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		contentType string
		want        float64
	}{
		"success: png":             {"image/png", 1},
		"success: jpeg":            {"image/jpeg", 1},
		"success: gif":             {"image/gif", 1},
		"success: microsoft icon":  {"image/vnd.microsoft.icon", 1},
		"success: x-icon":          {"image/x-icon", 1},
		"success: webp":            {"image/webp", 1},
		"success: unknown format":  {"image/future-unknown-format-42", 1},
		"success: svg":             {"image/svg+xml", 0},
		"success: not an image":    {"text/plain", 0},
		"success: no content type": {"", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := (Image{}).RenderPriority(nil, Metadata{ContentType: tt.contentType})
			if got != tt.want {
				t.Fatalf("RenderPriority(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

// TestImageTypeDetection covers the detection table's formats and the
// short-input guards of the sliced tests.
func TestImageTypeDetection(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		data string
		want string
	}{
		"success: jfif jpeg":              {"\xff\xd8\xff\xe0\x00\x10JFIFxxxx", "jpeg"},
		"success: exif jpeg":              {"\xff\xd8\xff\xe1\x00\x10Exifxxxx", "jpeg"},
		"success: raw jpeg":               {"\xff\xd8\xff\xdb", "jpeg"},
		"success: png":                    {"\x89PNG\r\n\x1a\n", "png"},
		"success: gif87a":                 {"GIF87a", "gif"},
		"success: gif89a":                 {"GIF89a", "gif"},
		"success: tiff big endian":        {"MM\x00\x2a", "tiff"},
		"success: tiff little endian":     {"II\x2a\x00", "tiff"},
		"success: sgi rgb":                {"\x01\xda\x00\x01", "rgb"},
		"success: pbm":                    {"P1\n1 1\n0", "pbm"},
		"success: pgm":                    {"P5 2 2 255 ", "pgm"},
		"success: ppm":                    {"P6\t1 1 255 ", "ppm"},
		"success: sun raster":             {"\x59\xa6\x6a\x95", "rast"},
		"success: xbm":                    {"#define test_width 16", "xbm"},
		"success: bmp":                    {"BM\x00\x00", "bmp"},
		"success: webp":                   {"RIFF\x00\x00\x00\x00WEBPVP8 ", "webp"},
		"success: exr":                    {"\x76\x2f\x31\x01", "exr"},
		"success: ico":                    {"\x00\x00\x01\x00\x01\x00", "ico"},
		"success: unknown":                {"flibble", ""},
		"success: empty":                  {"", ""},
		"success: short jpeg slice":       {"\xff\xd8\xff\xe0\x00", ""},
		"success: short webp slice":       {"RIFF\x00\x00\x00\x00WEB", ""},
		"success: short pnm":              {"P1", ""},
		"success: pnm with bad separator": {"P1x", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := imageType([]byte(tt.data)); got != tt.want {
				t.Fatalf("imageType(%q) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}
