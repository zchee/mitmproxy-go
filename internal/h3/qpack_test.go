// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"bytes"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestQPACKContract(t *testing.T) {
	// RFC 9204 static table and literal field line representations.
	tests := map[string]struct {
		block []byte
		want  []HeaderField
	}{
		"empty field section": {block: []byte{0, 0}},
		"static method and path": {
			block: []byte{0, 0, 0xd1, 0xc1},
			want:  []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/"}},
		},
		"ordered duplicate literals": {
			block: []byte{0, 0, 0x25, 'x', '-', 'f', 'o', 'o', 1, '1', 0x25, 'x', '-', 'b', 'a', 'r', 1, '2', 0x25, 'x', '-', 'f', 'o', 'o', 1, '3'},
			want:  []HeaderField{{Name: "x-foo", Value: "1"}, {Name: "x-bar", Value: "2"}, {Name: "x-foo", Value: "3"}},
		},
		"uppercase remains literal": {
			block: []byte{0, 0, 0x25, 'X', '-', 'F', 'o', 'o', 1, '1'},
			want:  []HeaderField{{Name: "X-Foo", Value: "1"}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(tt.block)
			got, err := decodeHeaders(tt.block)
			if err != nil {
				t.Fatalf("decodeHeaders(%x): %v", tt.block, err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("decoded fields (-want +got):\n%s", diff)
			}
			if !bytes.Equal(before, tt.block) {
				t.Fatal("decoder modified its borrowed input")
			}
			encoded, err := encodeHeaders(tt.want)
			if err != nil {
				t.Fatalf("encodeHeaders(%v): %v", tt.want, err)
			}
			if !bytes.HasPrefix(encoded, []byte{0, 0}) {
				t.Fatalf("dynamic table prefix = %x, want zero insert count and base", encoded)
			}
			roundTrip, err := decodeHeaders(encoded)
			if err != nil {
				t.Fatalf("decode encoded section: %v", err)
			}
			if diff := gocmp.Diff(tt.want, roundTrip); diff != "" {
				t.Fatalf("round-trip fields (-want +got):\n%s", diff)
			}
		})
	}
}

func TestQPACKMalformed(t *testing.T) {
	// qpack v0.6.0 decoder_test.go pins nonzero prefixes, dynamic references,
	// invalid static indexes and truncated literal representations.
	tests := map[string]struct{ block []byte }{
		"missing prefix":                {},
		"truncated prefix":              {block: []byte{0}},
		"nonzero required insert count": {block: []byte{1, 0}},
		"nonzero delta base":            {block: []byte{0, 1}},
		"dynamic indexed field":         {block: []byte{0, 0, 0x94}},
		"dynamic name reference":        {block: []byte{0, 0, 0x41}},
		"unknown representation":        {block: []byte{0, 0, 0x10}},
		"invalid static index":          {block: []byte{0, 0, 0xff, 0x25}},
		"truncated literal name":        {block: []byte{0, 0, 0x25, 'x'}},
		"truncated literal value":       {block: []byte{0, 0, 0x21, 'x', 2, 'a'}},
		"invalid huffman padding":       {block: []byte{0, 0, 0x21, 'x', 0x81, 0xff}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := decodeHeaders(tt.block); err == nil || got != nil {
				t.Fatalf("decodeHeaders(%x) = %v, %v; want nil fields and error", tt.block, got, err)
			}
		})
	}
}

func TestQPACKBounds(t *testing.T) {
	tests := map[string]struct {
		fields []HeaderField
		block  []byte
	}{
		"encoded section over cap": {block: bytes.Repeat([]byte{0}, qpackHeaderLimit+1)},
		"decoded field over cap":   {fields: []HeaderField{{Name: "x", Value: strings.Repeat("a", qpackHeaderLimit)}}},
		"decoded cumulative overhead over cap": {
			block: append([]byte{0, 0}, bytes.Repeat([]byte{0xc1}, qpackHeaderLimit/34+1)...),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.block != nil {
				if fields, err := decodeHeaders(tt.block); err == nil || fields != nil {
					t.Fatalf("oversized decoded block: got %d fields, %v; want nil and error", len(fields), err)
				}
			} else if block, err := encodeHeaders(tt.fields); err == nil || block != nil {
				t.Fatalf("oversized fields: got %d encoded bytes, %v; want nil and error", len(block), err)
			}
		})
	}
}
