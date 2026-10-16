// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"
)

func TestProtobufNodeReencode(t *testing.T) {
	tests := map[string]struct {
		text string
		data []byte
	}{
		"varint":                    {"1: 150  # !sint: 75\n", []byte("\x08\x96\x01")},
		"varint_zigzag_negative":    {"1: 11  # !sint: -6\n", []byte("\x08\x0b")},
		"varint_int64_negative":     {"1: -2  # u64: 18446744073709551614\n", []byte("\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01")},
		"binary":                    {"6: !binary '010203'\n", []byte("\x32\x03\x01\x02\x03")},
		"string":                    {"1: hello\n", []byte("\x0a\x05hello")},
		"nested":                    {"5:\n  1: 42  # !sint: 21\n", []byte("\x2a\x02\x08\x2a")},
		"nested_twice":              {"5:\n  5:\n    1: 42  # !sint: 21\n", []byte("\x2a\x04\x2a\x02\x08\x2a")},
		"fixed64":                   {"3: !fixed64 -1.0  # u64: 13830554455654793216, i64: -4616189618054758400\n", []byte("\x19\x00\x00\x00\x00\x00\x00\xf0\xbf")},
		"fixed64_positive":          {"3: !fixed64 3.14159  # u64: 4614256650576692846\n", []byte("\x19\x6e\x86\x1b\xf0\xf9\x21\x09\x40")},
		"fixed64_no_float":          {"3: !fixed64 -1  # u64: 18446744073709551615\n", []byte("\x19\xff\xff\xff\xff\xff\xff\xff\xff")},
		"fixed64_positive_no_float": {"3: !fixed64 9221120237041090561\n", []byte("\x19\x01\x00\x00\x00\x00\x00\xf8\x7f")},
		"fixed32":                   {"2: !fixed32 -1.0  # u32: 3212836864, i32: -1082130432\n", []byte("\x15\x00\x00\x80\xbf")},
		"fixed32_positive":          {"2: !fixed32 3.14159  # u32: 1078530000\n", []byte("\x15\xd0\x0f\x49\x40")},
		"fixed32_no_float":          {"2: !fixed32 -1  # u32: 4294967295\n", []byte("\x15\xff\xff\xff\xff")},
		"fixed32_positive_no_float": {"2: !fixed32 2143289345\n", []byte("\x15\x01\x00\xc0\x7f")},
		"repeated_packed":           {"6: !binary 038e029ea705\n", []byte("\x32\x06\x03\x8e\x02\x9e\xa7\x05")},
		"repeated_varint":           {"1:\n- 1  # !sint: -1\n- 2  # !sint: 1\n- 3  # !sint: -2\n", []byte("\x08\x01\x08\x02\x08\x03")},
		"null omission":             {"1: null\n2: true\n", []byte{0x10, 1}},
		"empty nested":              {"1: {}\n", []byte{0x0a, 0}},
		"hex integer":               {"1: 0x96\n", []byte{8, 150, 1}},
		"zigzag edit":               {"1: !sint -6\n", []byte{8, 11}},
		"unknown numeric tag":       {"1: !varint 150\n", []byte{8, 150, 1}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tt.text), &node); err != nil {
				t.Fatal(err)
			}
			budget := &viewBudget{view: "Protobuf"}
			got, err := encodeProtobufNode(&node, nil, budget)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.data, got); diff != "" {
				t.Fatalf("wire mismatch (-want +got):\n%s", diff)
			}
			if budget.bytes != len(got) {
				t.Fatalf("nested output counted more than once: budget=%d, output=%d", budget.bytes, len(got))
			}
		})
	}
}

func TestProtobufNodeReencodeErrors(t *testing.T) {
	tests := map[string]struct{ text string }{
		"not mapping":       {"[]"},
		"zero key":          {"0: 1"},
		"negative key":      {"-1: 1"},
		"oversized key":     {"536870912: 1"},
		"fractional key":    {"1.5: 1"},
		"unknown name":      {"unknown: 1"},
		"odd binary":        {"1: !binary '123'"},
		"invalid binary":    {"1: !binary zz"},
		"invalid fixed":     {"1: !fixed64 hello"},
		"fractional zigzag": {"1: !sint 1.5"},
		"oversized zigzag":  {"1: !sint 18446744073709551615"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tt.text), &node); err != nil {
				t.Fatal(err)
			}
			if data, err := encodeProtobufNode(&node, nil, &viewBudget{view: "Protobuf"}); err == nil || data != nil {
				t.Fatalf("got data=%x error=%v; want failure without partial data", data, err)
			}
		})
	}
}

func TestProtobufNodeEncodeLimits(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte("1: {1: 1}"), &node); err != nil {
		t.Fatal(err)
	}
	budget := &viewBudget{view: "Protobuf", bytes: maxViewBytes - 3}
	if data, err := encodeProtobufNode(&node, nil, budget); data != nil || err == nil {
		t.Fatalf("output limit: data=%x err=%v", data, err)
	} else if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("expected typed limit, got %v", err)
	}
	if budget.bytes != maxViewBytes-3 {
		t.Fatal("failed output reservation changed budget")
	}
}
