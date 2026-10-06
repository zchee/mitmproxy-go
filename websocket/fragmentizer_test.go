// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"math"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestFragmentizer(t *testing.T) {
	tests := map[string]struct {
		lengths []int
		content []byte
		want    []int
	}{
		"empty edited message":            {[]int{3}, nil, []int{0}},
		"keep sizes for same length edit": {[]int{3, 3}, []byte("foobaz"), []int{3, 3}},
		"keep empty fragments":            {[]int{0, 3, 0, 3, 0}, []byte("foobar"), []int{0, 3, 0, 3, 0}},
		"all empty fragments":             {[]int{0, 0, 0}, nil, []int{0, 0, 0}},
		"length changing edit":            {[]int{3}, bytes.Repeat([]byte("x"), 8001), []int{4000, 4000, 1}},
		"exact chunk boundary":            {nil, bytes.Repeat([]byte("x"), 8000), []int{4000, 4000}},
		"empty injection":                 {nil, nil, []int{0}},
		"nonempty injection":              {nil, []byte("hello"), []int{5}},
		"compressed plaintext boundary":   {[]int{6}, []byte("foobaz"), []int{6}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := NewFragmentizer(tt.lengths)
			if err != nil {
				t.Fatal(err)
			}
			var sizes []int
			var content []byte
			for fragment, fin := range f.Fragments(tt.content) {
				sizes = append(sizes, len(fragment))
				content = append(content, fragment...)
				if fin != (len(sizes) == len(tt.want)) {
					t.Fatalf("fragment %d FIN=%v", len(sizes), fin)
				}
			}
			if diff := gocmp.Diff(tt.want, sizes); diff != "" {
				t.Fatal(diff)
			}
			if !bytes.Equal(tt.content, content) {
				t.Fatalf("content = %q, want %q", content, tt.content)
			}
		})
	}
}

func TestFragmentizerInvalidLengths(t *testing.T) {
	tests := map[string]struct{ lengths []int }{
		"negative": {[]int{1, -1}},
		"overflow": {[]int{math.MaxInt, 1}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewFragmentizer(tt.lengths); err == nil {
				t.Fatal("accepted invalid lengths")
			}
		})
	}
}

func TestFragmentizerCopiesLengthsAndStops(t *testing.T) {
	lengths := []int{1, 2}
	f, err := NewFragmentizer(lengths)
	if err != nil {
		t.Fatal(err)
	}
	lengths[0] = 3
	count := 0
	for part, fin := range f.Fragments([]byte("abc")) {
		count++
		if string(part) != "a" || fin {
			t.Fatalf("first fragment = %q, FIN=%v", part, fin)
		}
		break
	}
	if count != 1 {
		t.Fatalf("yield count=%d", count)
	}
}
