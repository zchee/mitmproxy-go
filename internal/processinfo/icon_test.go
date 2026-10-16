// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestProcessPNG(t *testing.T) {
	tests := map[string]struct {
		bounds image.Rectangle
		want   image.Point
	}{
		"square":    {bounds: image.Rect(0, 0, 64, 64), want: image.Pt(32, 32)},
		"landscape": {bounds: image.Rect(0, 0, 64, 32), want: image.Pt(32, 16)},
		"portrait":  {bounds: image.Rect(10, 20, 42, 84), want: image.Pt(16, 32)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			source := image.NewRGBA(test.bounds)
			for y := test.bounds.Min.Y; y < test.bounds.Max.Y; y++ {
				for x := test.bounds.Min.X; x < test.bounds.Max.X; x++ {
					source.SetRGBA(x, y, color.RGBA{R: 255, A: 255})
				}
			}
			data, err := iconPNG(source)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) > maxPNGBytes {
				t.Fatalf("PNG size = %d, limit = %d", len(data), maxPNGBytes)
			}
			decoded, err := png.Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("decode PNG: %v", err)
			}
			if decoded.Bounds().Size() != test.want {
				t.Fatalf("decoded size = %v, want %v", decoded.Bounds().Size(), test.want)
			}
			if got := color.RGBAModel.Convert(decoded.At(0, 0)); got != (color.RGBA{R: 255, A: 255}) {
				t.Fatalf("decoded corner = %v, want red", got)
			}
		})
	}
}

func TestProcessPNGWriterBound(t *testing.T) {
	writer := boundedPNG{limit: 4}
	if count, err := writer.Write([]byte("four")); count != 4 || err != nil {
		t.Fatalf("at limit = %d, %v", count, err)
	}
	if count, err := writer.Write([]byte("x")); count != 0 || err == nil {
		t.Fatalf("over limit = %d, %v", count, err)
	}
	if writer.String() != "four" {
		t.Fatalf("overflow mutated output to %q", writer.String())
	}
}
