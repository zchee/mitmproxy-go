// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// The rows below were produced by the pinned Rust Protobuf view (mitmproxy-rs
// 51fe2b7) with testdata/protobuf-oracle/all.proto as its definitions. For
// each schema-less YAML text, the Rust view encoded the wire bytes, rendered
// them without and with the definitions, and encoded the rendering with the
// definitions again.
var protobufSchemaOracle = []struct {
	text, wire, plain, schema, again string
	plainErr, schemaErr, againErr    bool
}{
	{text: "1: 150", wire: "089601", plain: "1: 150  # !sint: 75\n", plainErr: false, schema: "i32: 150\n", schemaErr: false, again: "089601", againErr: false},
	{text: "1: -5", wire: "08fbffffffffffffffff01", plain: "1: -5  # u64: 18446744073709551611\n", plainErr: false, schema: "i32: -5\n", schemaErr: false, again: "08fbffffffffffffffff01", againErr: false},
	{text: "2: -7", wire: "10f9ffffffffffffffff01", plain: "2: -7  # u64: 18446744073709551609\n", plainErr: false, schema: "i64: -7\n", schemaErr: false, again: "10f9ffffffffffffffff01", againErr: false},
	{text: "3: 4294967295", wire: "18ffffffff0f", plain: "3: 4294967295  # !sint: -2147483648\n", plainErr: false, schema: "u32: 4294967295\n", schemaErr: false, again: "18ffffffff0f", againErr: false},
	{text: "4: 18446744073709551615", wire: "20ffffffffffffffffff01", plain: "4: -1  # u64: 18446744073709551615\n", plainErr: false, schema: "u64: 18446744073709551615\n", schemaErr: false, again: "20ffffffffffffffffff01", againErr: false},
	{text: "5: !sint -3", wire: "2805", plain: "5: 5  # !sint: -3\n", plainErr: false, schema: "s32: -3\n", schemaErr: false, again: "28fdffffffffffffffff01", againErr: false},
	{text: "6: !sint 12345", wire: "30f2c001", plain: "6: 24690  # !sint: 12345\n", plainErr: false, schema: "s64: 12345\n", schemaErr: false, again: "30b960", againErr: false},
	{text: "7: !fixed32 5", wire: "3d05000000", plain: "7: !fixed32 5\n", plainErr: false, schema: "f32: 5\n", schemaErr: false, again: "3d05000000", againErr: false},
	{text: "8: !fixed64 7", wire: "410700000000000000", plain: "8: !fixed64 7\n", plainErr: false, schema: "f64: 7\n", schemaErr: false, again: "410700000000000000", againErr: false},
	{text: "9: !fixed32 -1", wire: "4dffffffff", plain: "9: !fixed32 -1  # u32: 4294967295\n", plainErr: false, schema: "sf32: -1\n", schemaErr: false, again: "4dffffffff", againErr: false},
	{text: "10: !fixed64 -2", wire: "51feffffffffffffff", plain: "10: !fixed64 -2  # u64: 18446744073709551614\n", plainErr: false, schema: "sf64: -2\n", schemaErr: false, again: "51feffffffffffffff", againErr: false},
	{text: "11: !fixed32 0.1", wire: "5dcdcccc3d", plain: "11: !fixed32 0.1  # u32: 1036831949\n", plainErr: false, schema: "fl: 0.10000000149011612\n", schemaErr: false, again: "5dcdcccc3d", againErr: false},
	{text: "11: !fixed32 1.5", wire: "5d0000c03f", plain: "11: !fixed32 1.5  # u32: 1069547520\n", plainErr: false, schema: "fl: 1.5\n", schemaErr: false, again: "5d0000c03f", againErr: false},
	{text: "11: !fixed32 -2.25", wire: "5d000010c0", plain: "11: !fixed32 -2.25  # u32: 3222274048, i32: -1072693248\n", plainErr: false, schema: "fl: -2.25\n", schemaErr: false, again: "5d000010c0", againErr: false},
	{text: "12: !fixed64 0.1", wire: "619a9999999999b93f", plain: "12: !fixed64 0.1  # u64: 4591870180066957722\n", plainErr: false, schema: "db: 0.1\n", schemaErr: false, again: "619a9999999999b93f", againErr: false},
	{text: "12: !fixed64 1e300", wire: "619c7500883ce4377e", plain: "12: !fixed64 9094988921128908188  # f64: 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0\n", plainErr: false, schema: "db: 1e300\n", schemaErr: false, again: "619c7500883ce4377e", againErr: false},
	{text: "12: !fixed64 1e-7", wire: "6148afbc9af2d77a3e", plain: "12: !fixed64 4502148214488346440\n", plainErr: false, schema: "db: 1e-7\n", schemaErr: false, again: "6148afbc9af2d77a3e", againErr: false},
	{text: "11: !fixed32 .nan", wire: "5d0000c07f", plain: "11: !fixed32 2143289344\n", plainErr: false, schema: "fl: .nan\n", schemaErr: false, again: "5d0000c07f", againErr: false},
	{text: "12: !fixed64 .inf", wire: "61000000000000f07f", plain: "12: !fixed64 inf.0  # u64: 9218868437227405312\n", plainErr: false, schema: "db: .inf\n", schemaErr: false, again: "61000000000000f07f", againErr: false},
	{text: "13: true", wire: "6801", plain: "13: 1  # !sint: -1\n", plainErr: false, schema: "b: true\n", schemaErr: false, again: "6801", againErr: false},
	{text: "13: false", wire: "6800", plain: "13: 0  # !sint: 0\n", plainErr: false, schema: "b: false\n", schemaErr: false, again: "6800", againErr: false},
	{text: "14: hello", wire: "720568656c6c6f", plain: "14: hello\n", plainErr: false, schema: "str: hello\n", schemaErr: false, again: "720568656c6c6f", againErr: false},
	{text: "14: 'true'", wire: "720474727565", plain: "14: 'true'\n", plainErr: false, schema: "str: 'true'\n", schemaErr: false, again: "720474727565", againErr: false},
	{text: "14: '010'", wire: "7203303130", plain: "14: '010'\n", plainErr: false, schema: "str: '010'\n", schemaErr: false, again: "7203303130", againErr: false},
	{text: "14: \"a\\tb\"", wire: "7203610962", plain: "14: \"a\\tb\"\n", plainErr: false, schema: "str: \"a\\tb\"\n", schemaErr: false, again: "7203610962", againErr: false},
	{text: "14: |\n  a\n  b\n", wire: "7204610a620a", plain: "14: |\n  a\n  b\n", plainErr: false, schema: "str: |\n  a\n  b\n", schemaErr: false, again: "7204610a620a", againErr: false},
	{text: "14: ''", wire: "7200", plain: "14: ''\n", plainErr: false, schema: "str: ''\n", schemaErr: false, again: "7200", againErr: false},
	{text: "15: !binary 00ff", wire: "7a0200ff", plain: "15: !binary 00ff\n", plainErr: false, schema: "by: !binary 00ff\n", schemaErr: false, again: "7a0200ff", againErr: false},
	{text: "15: !binary ''", wire: "7a00", plain: "15: ''\n", plainErr: false, schema: "by: !binary ''\n", schemaErr: false, again: "7a00", againErr: false},
	{text: "16: 1", wire: "800101", plain: "16: 1  # !sint: -1\n", plainErr: false, schema: "color: GREEN\n", schemaErr: false, again: "820105475245454e", againErr: false},
	{text: "16: 7", wire: "800107", plain: "16: 7  # !sint: -4\n", plainErr: false, schema: "color: 7\n", schemaErr: false, again: "800107", againErr: false},
	{text: "17: {1: 5, 2: x}", wire: "8a01050805120178", plain: "17:\n  1: 5  # !sint: -3\n  2: x\n", plainErr: false, schema: "inner:\n  a: 5\n  s: x\n", schemaErr: false, again: "8a01050805120178", againErr: false},
	{text: "17: {}", wire: "8a0100", plain: "17: ''\n", plainErr: false, schema: "inner: {}\n", schemaErr: false, again: "8a0100", againErr: false},
	{text: "18: [1, 2, 3]", wire: "900101900102900103", plain: "18:\n- 1  # !sint: -1\n- 2  # !sint: 1\n- 3  # !sint: -2\n", plainErr: false, schema: "ri:\n- 1\n- 2\n- 3\n", schemaErr: false, again: "900101900102900103", againErr: false},
	{text: "18: !binary 010203", wire: "920103010203", plain: "18: !binary '010203'\n", plainErr: false, schema: "ri:\n- 1\n- 2\n- 3\n", schemaErr: false, again: "900101900102900103", againErr: false},
	{text: "19: [{1: 1}, {1: 2}]", wire: "9a010208019a01020802", plain: "19:\n- 1: 1  # !sint: -1\n- 1: 2  # !sint: 1\n", plainErr: false, schema: "rinner:\n- a: 1\n- a: 2\n", schemaErr: false, again: "", againErr: true},
	{text: "20: {1: k, 2: 3}", wire: "a201050a016b1003", plain: "20:\n  1: k\n  2: 3  # !sint: -2\n", plainErr: false, schema: "m:\n  k: 3\n", schemaErr: false, again: "", againErr: true},
	{text: "20: [{1: b, 2: 2}, {1: a, 2: 1}]", wire: "a201050a01621002a201050a01611001", plain: "20:\n- 1: b\n  2: 2  # !sint: 1\n- 1: a\n  2: 1  # !sint: -1\n", plainErr: false, schema: "m:\n  a: 1\n  b: 2\n", schemaErr: false, again: "", againErr: true},
	{text: "21: [x, 'y']", wire: "aa010178aa010179", plain: "21:\n- x\n- y\n", plainErr: false, schema: "rs:\n- x\n- y\n", schemaErr: false, again: "aa010178aa010179", againErr: false},
	{text: "99: 5", wire: "980605", plain: "99: 5  # !sint: -3\n", plainErr: false, schema: "99: 5  # !sint: -3\n", schemaErr: false, again: "980605", againErr: false},
	{text: "1: 1\n99: zz", wire: "08019a06027a7a", plain: "1: 1  # !sint: -1\n99: zz\n", plainErr: false, schema: "i32: 1\n99: zz\n", schemaErr: false, again: "08019a06027a7a", againErr: false},
	{text: "14: 5", wire: "7005", plain: "14: 5  # !sint: -3\n", plainErr: false, schema: "14: 5  # !sint: -3\n", schemaErr: false, again: "7005", againErr: false},
	{text: "1: 150\n14: s\n17: {1: 2}", wire: "0896017201738a01020802", plain: "1: 150  # !sint: 75\n14: s\n17:\n  1: 2  # !sint: 1\n", plainErr: false, schema: "i32: 150\nstr: s\ninner:\n  a: 2\n", schemaErr: false, again: "0896017201738a01020802", againErr: false},
	{text: "1: 0", wire: "0800", plain: "1: 0  # !sint: 0\n", plainErr: false, schema: "i32: 0\n", schemaErr: false, again: "0800", againErr: false},
	{text: "6: !sint 0", wire: "3000", plain: "6: 0  # !sint: 0\n", plainErr: false, schema: "s64: 0\n", schemaErr: false, again: "3000", againErr: false},
}

// Named rows are YAML texts encoded with the definitions.
var protobufSchemaOracleNamed = []struct {
	text, want string
	wantErr    bool
}{
	{text: "i32: 5", want: "0805"},
	{text: "i64: -1", want: "10ffffffffffffffffff01"},
	{text: "fl: 1.5", want: "5d0000c03f"},
	{text: "fl: 2", want: "5d02000000"},
	{text: "db: 2", want: "610200000000000000"},
	{text: "db: 0.1", want: "619a9999999999b93f"},
	{text: "sf32: -1", want: "4dffffffff"},
	{text: "sf64: -1", want: "51ffffffffffffffff"},
	{text: "f32: 3", want: "3d03000000"},
	{text: "f64: 3", want: "410300000000000000"},
	{text: "f32: 1.5", want: "3d0000c03f"},
	{text: "inner: {a: 1, s: t}", want: "8a01050801120174"},
	{text: "rinner: [{a: 1}]", wantErr: true},
	{text: "m: {k: 1}", wantErr: true},
	{text: "color: GREEN", want: "820105475245454e"},
	{text: "str: 5", want: "7005"},
	{text: "b: 1", want: "6801"},
	{text: "ri: [1, 2]", want: "900101900102"},
	{text: "by: !binary 0a0b", want: "7a020a0b"},
	{text: "'14': x", want: "720178"},
	{text: "1: !varint 7", want: "0807"},
	{text: "i32: !fixed32 1", want: "0d01000000"},
	{text: "unknownname: 1", wantErr: true},
	{text: "17: {a: 1}", want: "8a01020801"},
	{text: "i32: null", want: ""},
	{text: "i32: [1, 2]", want: "08010802"},
	{text: "i32: 1.5", want: "09000000000000f83f"},
	{text: "str: [a, b]", want: "720161720162"},
	{text: "rs: c", want: "aa010163"},
	{text: "inner: [{a: 1}, {a: 2}]", want: "8a010208018a01020802"},
}

// Invalid rows are YAML texts the Rust view rejects without definitions.
var protobufSchemaOracleInvalid = []string{
	"1: 1\n1: 2",
}

func TestProtobufSchemaOracle(t *testing.T) {
	definitions := Metadata{ProtobufDefinitions: filepath.Join("testdata", "protobuf-oracle", "all.proto")}
	for _, tt := range protobufSchemaOracle {
		t.Run(tt.text, func(t *testing.T) {
			wire, err := Protobuf{}.Reencode(tt.text, Metadata{})
			if err != nil {
				t.Fatalf("Reencode without definitions: %v", err)
			}
			if diff := cmp.Diff(tt.wire, hex.EncodeToString(wire)); diff != "" {
				t.Fatalf("Reencode without definitions (-rust +go):\n%s", diff)
			}
			for _, rendering := range []struct {
				name     string
				metadata Metadata
				want     string
				wantErr  bool
			}{{"plain", Metadata{}, tt.plain, tt.plainErr}, {"schema", definitions, tt.schema, tt.schemaErr}} {
				got, err := Protobuf{}.Prettify(wire, rendering.metadata)
				if rendering.wantErr {
					if err == nil {
						t.Fatalf("Prettify %s = %q, want an error", rendering.name, got)
					}
					continue
				}
				if err != nil {
					t.Fatalf("Prettify %s: %v", rendering.name, err)
				}
				if diff := cmp.Diff(rendering.want, got); diff != "" {
					t.Fatalf("Prettify %s (-rust +go):\n%s", rendering.name, diff)
				}
			}
			if tt.schemaErr {
				return
			}
			again, err := Protobuf{}.Reencode(tt.schema, definitions)
			if tt.againErr {
				if err == nil {
					t.Fatalf("Reencode with definitions = %x, want an error", again)
				}
				return
			}
			if err != nil {
				t.Fatalf("Reencode with definitions: %v", err)
			}
			if diff := cmp.Diff(tt.again, hex.EncodeToString(again)); diff != "" {
				t.Fatalf("Reencode with definitions (-rust +go):\n%s", diff)
			}
		})
	}
	for _, tt := range protobufSchemaOracleNamed {
		t.Run("named/"+tt.text, func(t *testing.T) {
			got, err := Protobuf{}.Reencode(tt.text, definitions)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Reencode = %x, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, hex.EncodeToString(got)); diff != "" {
				t.Fatalf("Reencode (-rust +go):\n%s", diff)
			}
		})
	}
	for _, text := range protobufSchemaOracleInvalid {
		t.Run("invalid/"+text, func(t *testing.T) {
			got, err := Protobuf{}.Reencode(text, Metadata{})
			if err == nil || !strings.HasPrefix(err.Error(), "Invalid YAML: ") {
				t.Fatalf("Reencode = %x, %v; want an Invalid YAML error", got, err)
			}
		})
	}
}
