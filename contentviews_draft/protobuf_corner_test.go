// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zchee/mitmproxy-go/contentviews"
)

func TestProtobufCornerOracle(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want string
		fail bool
	}{
		"empty group":                {data: []byte{0x0b, 0x0c}, want: "{}\n"},
		"nonempty group":             {data: []byte{0x0b, 0x10, 1, 0x0c}, want: "{}\n"},
		"mismatched group end":       {data: []byte{0x0b, 0x14}, want: "{}\n"},
		"nested group":               {data: []byte{0x0b, 0x13, 0x14, 0x0c}, want: "{}\n"},
		"unterminated group":         {data: []byte{0x0b}, fail: true},
		"unexpected group end":       {data: []byte{0x0c}, fail: true},
		"mixed varint and packed":    {data: []byte{8, 1, 10, 1, 'a'}, want: "1:\n- 1  # !sint: -1\n- 97  # !sint: -49\n"},
		"packed before varint":       {data: []byte{10, 1, 'a', 8, 1}, want: "1:\n- 97  # !sint: -49\n- 1  # !sint: -1\n"},
		"incompatible numeric wire":  {data: []byte{8, 1, 13, 1, 0, 0, 0}, fail: true},
		"first nested descriptor":    {data: []byte{10, 2, 8, 1, 10, 2, 16, 1}, want: "1:\n- 1: 1  # !sint: -1\n- {}\n"},
		"empty first descriptor":     {data: []byte{10, 0, 10, 2, 8, 1}, want: "1:\n- {}\n- {}\n"},
		"nested descriptor mismatch": {data: []byte{10, 2, 8, 1, 10, 3, 10, 1, 'a'}, fail: true},
		"vertical tab binary":        {data: []byte{10, 1, 11}, want: "1: !binary 0b\n"},
		"fixed32 infinity":           {data: []byte{0x15, 0, 0, 0x80, 0x7f}, want: "2: !fixed32 inf.0  # u32: 2139095040\n"},
		"fixed32 negative infinity":  {data: []byte{0x15, 0, 0, 0x80, 0xff}, want: "2: !fixed32 -inf.0  # u32: 4286578688, i32: -8388608\n"},
		"fixed64 infinity":           {data: []byte{0x19, 0, 0, 0, 0, 0, 0, 0xf0, 0x7f}, want: "3: !fixed64 inf.0  # u64: 9218868437227405312\n"},
		"fixed64 negative infinity":  {data: []byte{0x19, 0, 0, 0, 0, 0, 0, 0xf0, 0xff}, want: "3: !fixed64 -inf.0  # u64: 18442240474082181120, i64: -4503599627370496\n"},
		"fixed32 NaN":                {data: []byte{0x15, 0, 0, 0xc0, 0x7f}, want: "2: !fixed32 2143289344\n"},
		"fixed32 negative NaN":       {data: []byte{0x15, 0, 0, 0xc0, 0xff}, want: "2: !fixed32 -4194304  # u32: 4290772992\n"},
		"fixed64 NaN":                {data: []byte{0x19, 0, 0, 0, 0, 0, 0, 0xf8, 0x7f}, want: "3: !fixed64 9221120237041090560\n"},
		"fixed64 negative NaN":       {data: []byte{0x19, 0, 0, 0, 0, 0, 0, 0xf8, 0xff}, want: "3: !fixed64 -2251799813685248  # u64: 18444492273895866368\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(tt.data)
			got, err := (Protobuf{yaml: &fixtureYAML{spacedComments: true}}).Prettify(tt.data, contentviews.Metadata{})
			if (err != nil) != tt.fail {
				t.Fatalf("render error=%v, want failure=%v", err, tt.fail)
			}
			if diff := cmp.Diff([]byte(tt.want), []byte(got)); diff != "" {
				t.Fatalf("literal oracle bytes differ (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(original, tt.data); diff != "" {
				t.Fatalf("input changed: %s", diff)
			}
		})
	}
}

func TestProtobufCornerBudgets(t *testing.T) {
	budget := &viewBudget{view: "Protobuf", nodes: maxViewNodes - 1}
	fields := []wireField{{number: 1, typ: protowire.VarintType, bits: 1}, {number: 1, typ: protowire.BytesType, data: []byte{2, 3}}}
	if values, err := protobufNumericNodes(fields, protowire.VarintType, true, budget); values != nil || err == nil {
		t.Fatalf("packed values bypassed budget: %v %v", values, err)
	} else if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("expected typed limit: %v", err)
	}
	if _, err := parseWire([]byte{0x0b, 0x13, 0x14, 0x0c}, &viewBudget{view: "Protobuf"}, maxViewDepth); err == nil {
		t.Fatal("group nesting bypassed depth limit")
	}
}

func TestFixtureCommentSpacing(t *testing.T) {
	input := []byte("key: 'text # not a comment'\nnumber: 1 # actual\nblock: |\n  text # not a comment\n")
	got, err := fixtureCommentGap(input)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("key: 'text # not a comment'\nnumber: 1  # actual\nblock: |\n  text # not a comment\n")
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("non-comment bytes changed: %s", diff)
	}
}
