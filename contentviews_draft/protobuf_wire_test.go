// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestProtobufWireRoundTrip(t *testing.T) {
	tests := map[string]struct {
		data []byte
	}{
		"varint":                    {[]byte("\x08\x96\x01")},
		"varint_zigzag_negative":    {[]byte("\x08\x0b")},
		"varint_int64_negative":     {[]byte("\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01")},
		"binary":                    {[]byte("\x32\x03\x01\x02\x03")},
		"string":                    {[]byte("\x0a\x05hello")},
		"nested":                    {[]byte("\x2a\x02\x08\x2a")},
		"nested_twice":              {[]byte("\x2a\x04\x2a\x02\x08\x2a")},
		"fixed64":                   {[]byte("\x19\x00\x00\x00\x00\x00\x00\xf0\xbf")},
		"fixed64_positive":          {[]byte("\x19\x6e\x86\x1b\xf0\xf9\x21\x09\x40")},
		"fixed64_no_float":          {[]byte("\x19\xff\xff\xff\xff\xff\xff\xff\xff")},
		"fixed64_positive_no_float": {[]byte("\x19\x01\x00\x00\x00\x00\x00\xf8\x7f")},
		"fixed32":                   {[]byte("\x15\x00\x00\x80\xbf")},
		"fixed32_positive":          {[]byte("\x15\xd0\x0f\x49\x40")},
		"fixed32_no_float":          {[]byte("\x15\xff\xff\xff\xff")},
		"fixed32_positive_no_float": {[]byte("\x15\x01\x00\xc0\x7f")},
		"repeated_packed":           {[]byte("\x32\x06\x03\x8e\x02\x9e\xa7\x05")},
		"repeated_varint":           {[]byte("\x08\x01\x08\x02\x08\x03")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(tt.data)
			fields, err := parseWire(tt.data, &viewBudget{view: "Protobuf"}, 0)
			if err != nil {
				t.Fatal(err)
			}
			var got []byte
			budget := &viewBudget{view: "Protobuf"}
			for _, field := range fields {
				got, err = appendWire(got, field, budget)
				if err != nil {
					t.Fatal(err)
				}
			}
			if diff := cmp.Diff(tt.data, got); diff != "" {
				t.Fatalf("wire mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(original, tt.data); diff != "" {
				t.Fatalf("input mutated (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProtobufWireErrors(t *testing.T) {
	tests := map[string]struct {
		data []byte
	}{
		"zero field":        {[]byte{0, 1}},
		"truncated tag":     {[]byte{0xff}},
		"truncated varint":  {[]byte{8, 0xff}},
		"overflow varint":   {[]byte{8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2}},
		"truncated fixed32": {[]byte{0x0d, 0, 0, 0}},
		"truncated fixed64": {[]byte{9, 0, 0, 0}},
		"truncated bytes":   {[]byte{0x0a, 2, 1}},
		"declared huge":     {[]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 7}},
		"invalid type":      {[]byte{0x0f}},
		"start group":       {[]byte{0x0b}},
		"end group":         {[]byte{0x0c}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseWire(tt.data, &viewBudget{view: "Protobuf"}, 0); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestProtobufWireOrder(t *testing.T) {
	fields, err := parseWire([]byte{0x10, 3, 0x08, 2, 0x10, 1}, &viewBudget{view: "Protobuf"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := make([][2]uint64, len(fields))
	for i, field := range fields {
		got[i] = [2]uint64{uint64(field.number), field.bits}
	}
	want := [][2]uint64{{1, 2}, {2, 3}, {2, 1}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("field order (-want +got):\n%s", diff)
	}
}

func TestProtobufWireLimits(t *testing.T) {
	tests := map[string]struct {
		budget viewBudget
		depth  int
		want   string
	}{
		"node limit":  {viewBudget{view: "Protobuf", nodes: maxViewNodes}, 0, "nodes"},
		"depth limit": {viewBudget{view: "Protobuf"}, maxViewDepth + 1, "depth"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fields, err := parseWire([]byte{8, 1}, &tt.budget, tt.depth)
			limit, ok := errors.AsType[*LimitError](err)
			if !ok || limit.Bound != tt.want {
				t.Fatalf("got fields=%v error=%v; want %s limit", fields, err, tt.want)
			}
			if fields != nil {
				t.Fatal("partial fields returned after limit failure")
			}
		})
	}
	budget := &viewBudget{view: "Protobuf", bytes: maxViewBytes - 1}
	got, err := appendWire(nil, wireField{number: 1, typ: protowire.VarintType, bits: 1}, budget)
	if _, ok := errors.AsType[*LimitError](err); !ok || got != nil {
		t.Fatalf("output limit returned %x, %v", got, err)
	}
	if budget.bytes != maxViewBytes-1 {
		t.Fatal("failed reservation changed budget")
	}
}
