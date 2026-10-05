// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestRaw ports test__view_raw.py, with malformed UTF-8 boundaries added.
func TestRaw(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want string
	}{
		"test_view_raw":               {[]byte("foo"), "foo"},
		"test_view_raw unicode":       {[]byte("🫠"), "🫠"},
		"test_view_raw invalid utf8":  {[]byte{255}, `\xff`},
		"truncated unicode":           {[]byte{0xf0, 0x9f, 0xab}, `\xf0\x9f\xab`},
		"valid replacement character": {[]byte("�"), "�"},
		"mixed unicode and invalid":   {[]byte{'a', 0xff, 0xc3, 0xa9}, `a\xffé`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := (Raw{}).Prettify(tt.data, Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
			if got := (Raw{}).RenderPriority(tt.data, Metadata{}); got != 0.1 {
				t.Fatalf("test_render_priority: got %v", got)
			}
		})
	}
}
