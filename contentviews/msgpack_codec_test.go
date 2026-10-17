// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/shamaton/msgpack/v3/def"
)

func TestMsgpackCodec(t *testing.T) {
	tests := map[string]struct {
		data   []byte
		scalar any
	}{
		"null":           {[]byte{0xc0}, nil},
		"boolean":        {[]byte{0xc3}, true},
		"unsigned_width": {[]byte{0xce, 0, 1, 0, 0}, uint32(65536)},
		"signed_width":   {[]byte{0xd1, 0xff, 0x7f}, int16(-129)},
		"float_width":    {[]byte{0xca, 0x3f, 0x80, 0, 0}, float32(1)},
		"string":         {[]byte{0xa1, 'x'}, "x"},
		"binary":         {[]byte{0xc4, 1, 'x'}, []byte{'x'}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := decodeMsgpackValue(test.data, newViewBudget("test"))
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.scalar, got.Scalar); diff != "" {
				t.Fatalf("scalar (-want +got):\n%s", diff)
			}
			encoded, err := encodeMsgpackValue(got, newViewBudget("test"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(test.data, encoded) {
				t.Fatalf("encoding: want %x got %x", test.data, encoded)
			}
		})
	}
}

func TestMsgpackOrderedContainers(t *testing.T) {
	tests := map[string][]byte{
		"duplicate_keys": {0x82, 0xa1, 'a', 1, 0xa1, 'a', 2},
		"compound_keys":  {0x81, 0x91, 1, 0xc0},
		"binary_key":     {0x81, 0xc4, 1, 0, 0xc3},
		"empty_array":    {0x90},
		"empty_map":      {0x80},
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			value, err := decodeMsgpackValue(data, newViewBudget("test"))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := encodeMsgpackValue(value, newViewBudget("test"))
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(data, encoded); diff != "" {
				t.Fatalf("ordered roundtrip (-want +got):\n%s", diff)
			}
			if len(value.Entries) == 2 && (value.Entries[0].Value.Scalar != uint8(1) || value.Entries[1].Value.Scalar != uint8(2)) {
				t.Fatalf("duplicate order lost: %#v", value)
			}
		})
	}
}

func TestMsgpackCodecLimits(t *testing.T) {
	tests := map[string]struct {
		data      []byte
		nodes     uint64
		depth     int
		wantLimit bool
	}{
		"declared_array":   {[]byte{0xdd, 0xff, 0xff, 0xff, 0xff}, 10, 64, true},
		"declared_map":     {[]byte{0xdf, 0xff, 0xff, 0xff, 0xff}, 10, 64, true},
		"truncated_string": {[]byte{0xdb, 0xff, 0xff, 0xff, 0xff}, 10, 64, false},
		"depth":            {[]byte{0x91, 0x90}, 10, 1, true},
		"trailing":         {[]byte{0xc0, 0xc0}, 10, 64, false},
		"reserved":         {[]byte{0xc1}, 10, 64, false},
		"extension":        {[]byte{0xd4, 1, 0}, 10, 64, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			budget := newViewBudget("test")
			budget.limits.Nodes, budget.limits.Depth = test.nodes, test.depth
			value, err := decodeMsgpackValue(test.data, budget)
			if err == nil {
				t.Fatalf("accepted malformed or over-budget input: %#v", value)
			}
			var limit *LimitError
			if errors.As(err, &limit) != test.wantLimit {
				t.Fatalf("unexpected error classification: %v", err)
			}
			if value.Elements != nil || value.Entries != nil || value.Scalar != nil {
				t.Fatal("published partial value")
			}
		})
	}
}

func TestMsgpackEncodingLimits(t *testing.T) {
	tests := map[string]struct {
		value msgpackValue
		limit uint64
	}{
		"output":                 {msgpackValue{Code: def.Str8, Scalar: "hello"}, 3},
		"unsupported_scalar":     {msgpackValue{Scalar: map[string]string{"a": "b"}}, 100},
		"inconsistent_container": {msgpackValue{Code: def.FixArray, Scalar: true}, 100},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			budget := newViewBudget("test")
			budget.limits.OutputBytes = test.limit
			data, err := encodeMsgpackValue(test.value, budget)
			if err == nil || data != nil {
				t.Fatalf("got %x, %v", data, err)
			}
		})
	}
}
