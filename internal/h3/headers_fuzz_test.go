// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"bytes"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func FuzzHeaders(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 0},
		{0, 0, 0xd1, 0xc1},
		{0, 0, 0x21, 'x', 1, 'a', 0x21, 'x', 1, 'b'},
		{0, 0, 0x21, 'X', 1, 'a'},
		{0},
		{1, 0},
		{0, 0, 0xff, 0x25},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, block []byte) {
		before := bytes.Clone(block)
		fields, err := decodeHeaders(block)
		if !bytes.Equal(before, block) {
			t.Fatal("decoder changed borrowed bytes")
		}
		if err != nil {
			if fields != nil {
				t.Fatal("failed decode exposed a partial field section")
			}
			return
		}
		var total int
		for _, field := range fields {
			total += len(field.Name) + len(field.Value) + 32
		}
		if total > MaxHeaderBytes {
			t.Fatalf("decoded field section size %d exceeds bound", total)
		}
		encoded, err := encodeHeaders(fields)
		if err != nil {
			return // Re-encoding valid fields can exceed the separate encoded bound.
		}
		roundTrip, err := decodeHeaders(encoded)
		if err != nil {
			t.Fatalf("decode encoded fields: %v", err)
		}
		if diff := gocmp.Diff(fields, roundTrip); diff != "" {
			t.Fatalf("ordered field round-trip (-want +got):\n%s", diff)
		}
	})
}
