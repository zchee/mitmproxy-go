// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestProtobufCornerOracle holds wire shapes outside the upstream vectors.
// The expected results were produced by the pinned Rust view (mitmproxy-rs
// 51fe2b7) through its public prettify and reencode calls; an empty want
// means the Rust view reports an error.
func TestProtobufCornerOracle(t *testing.T) {
	decodeTests := map[string]struct {
		input string
		want  string
	}{
		"empty_group":               {"0b0c", "{}\n"},
		"nonempty_group":            {"0b10010c", "{}\n"},
		"mismatched_group":          {"0b14", "{}\n"},
		"nested_group":              {"0b13140c", "{}\n"},
		"unterminated_group":        {"0b", ""},
		"unexpected_end_group":      {"0c", ""},
		"mixed_wire":                {"08010a0161", "1:\n- 1  # !sint: -1\n- 97  # !sint: -49\n"},
		"mixed_wire_reverse":        {"0a01610801", "1:\n- 97  # !sint: -49\n- 1  # !sint: -1\n"},
		"mixed_fixed":               {"08010d01000000", ""},
		"vertical_tab":              {"0a010b", "1: !binary 0b\n"},
		"fixed_infinity":            {"150000807f", "2: !fixed32 inf.0  # u32: 2139095040\n"},
		"fixed_negative_infinity":   {"15000080ff", "2: !fixed32 -inf.0  # u32: 4286578688, i32: -8388608\n"},
		"fixed64_infinity":          {"19000000000000f07f", "3: !fixed64 inf.0  # u64: 9218868437227405312\n"},
		"fixed64_negative_infinity": {"19000000000000f0ff", "3: !fixed64 -inf.0  # u64: 18442240474082181120, i64: -4503599627370496\n"},
		"fixed_nan":                 {"150000c07f", "2: !fixed32 2143289344\n"},
		"fixed_negative_nan":        {"150000c0ff", "2: !fixed32 -4194304  # u32: 4290772992\n"},
		"fixed64_nan":               {"19000000000000f87f", "3: !fixed64 9221120237041090560\n"},
		"fixed64_negative_nan":      {"19000000000000f8ff", "3: !fixed64 -2251799813685248  # u64: 18444492273895866368\n"},
		"nested_fields_vary":        {"0a0208010a021001", "1:\n- 1: 1  # !sint: -1\n- {}\n"},
		"nested_same_key_mismatch":  {"0a0208010a030a0161", ""},
		"nested_first_empty":        {"0a000a020801", "1:\n- {}\n- {}\n"},
	}
	for name, tt := range decodeTests {
		t.Run("prettify/"+name, func(t *testing.T) {
			input, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Protobuf{}.Prettify(input, Metadata{})
			if tt.want == "" {
				if err == nil {
					t.Fatalf("Prettify(%s) = %q, want an error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Prettify(%s): %v", tt.input, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Prettify(%s) (-rust +go):\n%s", tt.input, diff)
			}
		})
	}
	encodeTests := map[string]struct {
		text string
		want string
	}{
		"varint_tag":             {"1: !varint 150", "089601"},
		"binary_unquoted_digits": {"1: !binary 010203", "0a03010203"},
		"binary_quoted_digits":   {"1: !binary '010203'", "0a03010203"},
		"hex_integer":            {"1: 0x96", "089601"},
		"fixed_infinity":         {"1: !fixed32 .inf", "0d0000807f"},
	}
	for name, tt := range encodeTests {
		t.Run("reencode/"+name, func(t *testing.T) {
			got, err := Protobuf{}.Reencode(tt.text, Metadata{})
			if err != nil {
				t.Fatalf("Reencode(%q): %v", tt.text, err)
			}
			if diff := cmp.Diff(tt.want, hex.EncodeToString(got)); diff != "" {
				t.Fatalf("Reencode(%q) (-rust +go):\n%s", tt.text, diff)
			}
		})
	}
}
