// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestHexViews ports hex_dump.rs and hex_stream.rs at the pinned Rust commit.
func TestHexViews(t *testing.T) {
	tests := map[string]struct {
		view View
		data []byte
		want string
	}{
		"prettify_simple":       {HexDump{}, []byte("abcd"), "0000:   61 62 63 64                                          abcd"},
		"prettify_empty":        {HexDump{}, nil, ""},
		"test_hex_stream":       {HexStream{}, []byte("foo"), "666f6f"},
		"test_hex_stream_empty": {HexStream{}, nil, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tt.view.Prettify(tt.data, Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestHexStreamReencode(t *testing.T) {
	tests := map[string]struct {
		input string
		want  []byte
		fail  bool
	}{
		"test_hex_stream_reencode":               {"666f6f", []byte("foo"), false},
		"test_hex_stream_reencode_with_newlines": {"666f6f\r\n", []byte("foo"), false},
		"test_hex_stream_reencode_uneven_chars":  {"666f6", nil, true},
		"uppercase":                              {"666F6F", []byte("foo"), false},
		"invalid_digit":                          {"xx", nil, true},
		"embedded_whitespace":                    {"66 6f", nil, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := (HexStream{}).Reencode(tt.input, Metadata{})
			if (err != nil) != tt.fail {
				t.Fatalf("error=%v want failure=%v", err, tt.fail)
			}
			if !tt.fail {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestHexBinaryPriority(t *testing.T) {
	tests := map[string]struct {
		data   []byte
		binary bool
	}{
		"empty": {nil, false}, "ascii": {[]byte("foo"), false}, "control": {[]byte{0, 1, 2}, true},
		"exact_threshold":           {[]byte{0, 0, 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g'}, false},
		"unicode_is_binary_in_rust": {[]byte("日本語"), true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			want := 0.0
			if tt.binary {
				want = 0.5
			}
			if got := (HexDump{}).RenderPriority(tt.data, Metadata{}); got != want {
				t.Fatalf("got %v want %v", got, want)
			}
			want = 0
			if tt.binary {
				want = 0.4
			}
			if got := (HexStream{}).RenderPriority(tt.data, Metadata{}); got != want {
				t.Fatalf("got %v want %v", got, want)
			}
		})
	}
}
