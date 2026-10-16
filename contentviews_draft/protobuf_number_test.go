// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"
)

func TestProtobufNumber(t *testing.T) {
	tests := map[string]struct {
		data []byte
		text string
	}{
		"varint":                    {[]byte("\x08\x96\x01"), "1: 150  # !sint: 75\n"},
		"varint_zigzag_negative":    {[]byte("\x08\x0b"), "1: 11  # !sint: -6\n"},
		"varint_int64_negative":     {[]byte("\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01"), "1: -2  # u64: 18446744073709551614\n"},
		"fixed64":                   {[]byte("\x19\x00\x00\x00\x00\x00\x00\xf0\xbf"), "3: !fixed64 -1.0  # u64: 13830554455654793216, i64: -4616189618054758400\n"},
		"fixed64_positive":          {[]byte("\x19\x6e\x86\x1b\xf0\xf9\x21\x09\x40"), "3: !fixed64 3.14159  # u64: 4614256650576692846\n"},
		"fixed64_no_float":          {[]byte("\x19\xff\xff\xff\xff\xff\xff\xff\xff"), "3: !fixed64 -1  # u64: 18446744073709551615\n"},
		"fixed64_positive_no_float": {[]byte("\x19\x01\x00\x00\x00\x00\x00\xf8\x7f"), "3: !fixed64 9221120237041090561\n"},
		"fixed32":                   {[]byte("\x15\x00\x00\x80\xbf"), "2: !fixed32 -1.0  # u32: 3212836864, i32: -1082130432\n"},
		"fixed32_positive":          {[]byte("\x15\xd0\x0f\x49\x40"), "2: !fixed32 3.14159  # u32: 1078530000\n"},
		"fixed32_no_float":          {[]byte("\x15\xff\xff\xff\xff"), "2: !fixed32 -1  # u32: 4294967295\n"},
		"fixed32_positive_no_float": {[]byte("\x15\x01\x00\xc0\x7f"), "2: !fixed32 2143289345\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fields, err := parseWire(tt.data, &viewBudget{view: "Protobuf"}, 0)
			if err != nil {
				t.Fatal(err)
			}
			field := fields[0]
			node, err := protobufNumber(field)
			if err != nil {
				t.Fatal(err)
			}
			literal, err := protobufNumberLiteral(field)
			if err != nil {
				t.Fatal(err)
			}
			text := strconv.Itoa(int(field.number)) + ": " + literal + "\n"
			if diff := cmp.Diff(tt.text, text); diff != "" {
				t.Fatalf("YAML mismatch (-want +got):\n%s", diff)
			}
			typ, bits, err := protobufNumberBits(node)
			if err != nil {
				t.Fatal(err)
			}
			field.typ, field.bits = typ, bits
			got, err := appendWire(nil, field, &viewBudget{view: "Protobuf"})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.data, got); diff != "" {
				t.Fatalf("numeric wire mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProtobufNumberErrors(t *testing.T) {
	tests := map[string]struct {
		node yaml.Node
	}{
		"mapping":       {yaml.Node{Kind: yaml.MappingNode}},
		"invalid sint":  {yaml.Node{Kind: yaml.ScalarNode, Tag: "!sint", Value: "1.5"}},
		"sint overflow": {yaml.Node{Kind: yaml.ScalarNode, Tag: "!sint", Value: "18446744073709551615"}},
		"not number":    {yaml.Node{Kind: yaml.ScalarNode, Tag: "!fixed32", Value: "hello"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := protobufNumberBits(&tt.node); err == nil {
				t.Fatal("expected numeric conversion error")
			}
		})
	}
}
