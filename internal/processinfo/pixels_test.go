// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProcessIconPixels(t *testing.T) {
	tests := map[string]struct {
		color      []byte
		mask       []byte
		width      int
		height     int
		monochrome bool
		want       []byte
		wantError  bool
	}{
		"color_order": {
			color: []byte{1, 2, 3, 255}, width: 1, height: 1,
			want: []byte{3, 2, 1, 255},
		},
		"alpha_preserved": {
			color: []byte{10, 20, 30, 128}, mask: []byte{255, 255, 255, 255}, width: 1, height: 1,
			want: []byte{30, 20, 10, 128},
		},
		"legacy_opaque": {
			color: []byte{1, 2, 3, 0}, width: 1, height: 1,
			want: []byte{3, 2, 1, 255},
		},
		"legacy_transparent": {
			color: []byte{1, 2, 3, 0}, mask: []byte{255, 255, 255, 0}, width: 1, height: 1,
			want: []byte{0, 0, 0, 0},
		},
		"transparent_rgb_cleared": {
			color: []byte{1, 2, 3, 0, 4, 5, 6, 255}, width: 2, height: 1,
			want: []byte{0, 0, 0, 0, 6, 5, 4, 255},
		},
		"short_color": {color: []byte{1}, width: 1, height: 1, wantError: true},
		"short_mask":  {color: []byte{1, 2, 3, 255}, mask: []byte{1}, width: 1, height: 1, wantError: true},
		"monochrome_black": {
			mask: []byte{0, 0, 0, 0, 0, 0, 0, 0}, width: 1, height: 2, monochrome: true,
			want: []byte{0, 0, 0, 255},
		},
		"monochrome_white": {
			mask: []byte{0, 0, 0, 0, 255, 255, 255, 0}, width: 1, height: 2, monochrome: true,
			want: []byte{255, 255, 255, 255},
		},
		"monochrome_transparent": {
			mask: []byte{255, 255, 255, 0, 0, 0, 0, 0}, width: 1, height: 2, monochrome: true,
			want: []byte{0, 0, 0, 0},
		},
		"monochrome_inverting": {
			mask: []byte{255, 255, 255, 0, 255, 255, 255, 0}, width: 1, height: 2, monochrome: true, wantError: true,
		},
		"monochrome_odd_height": {mask: make([]byte, 12), width: 1, height: 3, monochrome: true, wantError: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := colorIcon(test.color, test.mask, test.width, test.height)
			if test.monochrome {
				got, err = monochromeIcon(test.mask, test.width, test.height)
			}
			if (err != nil) != test.wantError {
				t.Fatalf("pixel conversion error = %v, want error %t", err, test.wantError)
			}
			if test.wantError {
				return
			}
			if diff := cmp.Diff(test.want, got.Pix); diff != "" {
				t.Fatalf("RGBA pixels (-want +got):\n%s", diff)
			}
		})
	}
}
