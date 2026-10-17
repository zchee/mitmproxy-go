// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

// The value and its YAML text are the literal fixtures of the pinned Rust
// view (mitmproxy-contentviews/src/msgpack.rs).
var (
	testMsgPack = []byte{
		0x83,
		0xa4, 0x6e, 0x61, 0x6d, 0x65,
		0xa8, 0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x44, 0x6f, 0x65,
		0xa3, 0x61, 0x67, 0x65,
		0x1e,
		0xa4, 0x74, 0x61, 0x67, 0x73,
		0x92,
		0xa9, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72,
		0xa4, 0x72, 0x75, 0x73, 0x74,
	}
	testMsgPackYAML = "name: John Doe\nage: 30\ntags:\n- developer\n- rust\n"
)

// msgpackSemantic decodes MessagePack and returns a canonical form under the
// equality of the Rust view's YAML values.
func msgpackSemantic(t *testing.T, data []byte) string {
	t.Helper()
	budget := newViewBudget("MsgPack")
	value, err := decodeMsgpackValue(data, budget)
	if err != nil {
		t.Fatalf("decode %x: %v", data, err)
	}
	var key strings.Builder
	if err := writeMsgpackKey(&key, value, budget); err != nil {
		t.Fatalf("canonical form of %x: %v", data, err)
	}
	return key.String()
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(strings.ReplaceAll(text, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestMsgPack(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(t *testing.T){
			"test_msgpack_deserialize": func(t *testing.T) {
				got, err := MsgPack{}.Prettify(testMsgPack, Metadata{})
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(testMsgPackYAML, got); diff != "" {
					t.Fatalf("Prettify (-want +got):\n%s", diff)
				}
			},
			"test_msgpack_serialize": func(t *testing.T) {
				data, err := MsgPack{}.Reencode(testMsgPackYAML, Metadata{})
				if err != nil {
					t.Fatal(err)
				}
				value, err := decodeMsgpackValue(data, newViewBudget("MsgPack"))
				if err != nil {
					t.Fatal(err)
				}
				if !msgpackIsMap(value.Code) || len(value.Entries) != 3 {
					t.Fatalf("value is not a three-entry mapping: %+v", value)
				}
				got := map[string]any{}
				for _, entry := range value.Entries {
					key, ok := entry.Key.Scalar.(string)
					if !ok {
						t.Fatalf("non-string key %+v", entry.Key)
					}
					switch {
					case msgpackIsArray(entry.Value.Code):
						var items []any
						for _, element := range entry.Value.Elements {
							items = append(items, element.Scalar)
						}
						got[key] = items
					default:
						got[key] = entry.Value.Scalar
					}
				}
				want := map[string]any{"name": "John Doe", "age": uint8(30), "tags": []any{"developer", "rust"}}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Fatalf("reencoded value (-want +got):\n%s", diff)
				}
			},
			"test_msgpack_roundtrip": func(t *testing.T) {
				text, err := MsgPack{}.Prettify(testMsgPack, Metadata{})
				if err != nil {
					t.Fatal(err)
				}
				data, err := MsgPack{}.Reencode(text, Metadata{})
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(msgpackSemantic(t, testMsgPack), msgpackSemantic(t, data)); diff != "" {
					t.Fatalf("decoded values differ (-original +reencoded):\n%s", diff)
				}
			},
			"test_invalid_yaml": func(t *testing.T) {
				data, err := MsgPack{}.Reencode("@invalid_yaml", Metadata{})
				if err == nil || data != nil {
					t.Fatalf("Reencode = %x, %v; want an error", data, err)
				}
				if !strings.HasPrefix(err.Error(), "Invalid YAML") {
					t.Fatalf("error %q lacks the Invalid YAML prefix", err)
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})

	t.Run("view", func(t *testing.T) {
		view := MsgPack{}
		if diff := cmp.Diff([]string{"MsgPack", "yaml"}, []string{view.Name(), view.SyntaxHighlight()}); diff != "" {
			t.Fatalf("view identity (-want +got):\n%s", diff)
		}
		tests := map[string]struct {
			contentType string
			want        float64
		}{
			"msgpack":   {"application/msgpack", 1},
			"x-msgpack": {"application/x-msgpack", 1},
			"json":      {"application/json", 0},
			"none":      {"", 0},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				if got := view.RenderPriority(testMsgPack, Metadata{ContentType: tt.contentType}); got != tt.want {
					t.Fatalf("RenderPriority(%q) = %v, want %v", tt.contentType, got, tt.want)
				}
			})
		}
	})

	t.Run("registry", func(t *testing.T) {
		registry := NewRegistry()
		var names []string
		for _, view := range registry.views {
			names = append(names, view.name)
		}
		if len(names) < 2 || names[len(names)-2] != "dns" || names[len(names)-1] != "msgpack" {
			t.Fatalf("registry order %v does not append msgpack after dns", names)
		}
		request := &httpmsg.Request{RawContent: testMsgPack}
		request.Headers.Set("content-type", "application/msgpack")
		got := PrettifyMessage(request, nil, "auto", registry, 0)
		if got.Err != nil || got.ViewName != "MsgPack" || got.Text != testMsgPackYAML {
			t.Fatalf("auto selection = %+v", got)
		}
	})

	t.Run("oracle", func(t *testing.T) {
		t.Run("decode", func(t *testing.T) {
			for name, tt := range msgpackOracleDecode {
				t.Run(name, func(t *testing.T) {
					input := mustHex(t, tt.input)
					original := bytes.Clone(input)
					got, err := MsgPack{}.Prettify(input, Metadata{})
					if !bytes.Equal(input, original) {
						t.Fatal("input mutated")
					}
					if tt.wantErr != "" {
						if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr+": ") {
							t.Fatalf("Prettify(%s) = %q, %v; want a %q error", tt.input, got, err, tt.wantErr)
						}
						return
					}
					if err != nil {
						t.Fatalf("Prettify(%s): %v", tt.input, err)
					}
					if diff := cmp.Diff(tt.want, got); diff != "" {
						t.Fatalf("Prettify(%s) (-rust +go):\n%s", tt.input, diff)
					}
					data, err := MsgPack{}.Reencode(got, Metadata{})
					if err != nil {
						t.Fatalf("Reencode(%q): %v", got, err)
					}
					if diff := cmp.Diff(msgpackSemantic(t, input), msgpackSemantic(t, data)); diff != "" {
						t.Fatalf("decode, reencode, decode (-original +reencoded):\n%s", diff)
					}
				})
			}
		})
		t.Run("encode", func(t *testing.T) {
			for name, tt := range msgpackOracleEncode {
				t.Run(name, func(t *testing.T) {
					data, err := MsgPack{}.Reencode(tt.text, Metadata{})
					if tt.wantErr {
						if err == nil || data != nil || !strings.HasPrefix(err.Error(), "Invalid YAML: ") {
							t.Fatalf("Reencode(%q) = %x, %v; want an Invalid YAML error", tt.text, data, err)
						}
						return
					}
					if err != nil {
						t.Fatalf("Reencode(%q): %v", tt.text, err)
					}
					if diff := cmp.Diff(tt.want, hex.EncodeToString(data)); diff != "" {
						t.Fatalf("Reencode(%q) (-rust +go):\n%s", tt.text, diff)
					}
				})
			}
		})
	})

	// These cases differ from the Rust view on purpose or through the YAML
	// emitter; each states the Rust result it replaces.
	t.Run("deviation", func(t *testing.T) {
		decodeTests := map[string]struct {
			input   string
			want    string
			wantErr string
		}{
			// Rust: invalid type: byte array.
			"binary uses the standard tag": {input: "c403010203", want: "!!binary AQID\n"},
			"empty binary":                 {input: "c400", want: "!!binary ''\n"},
			// Rust decodes the first value and ignores the rest.
			"trailing nil is refused":   {input: "c0c0", wantErr: "Failed to deserialize MsgPack: MsgPack decoding: trailing bytes"},
			"trailing value is refused": {input: "01c0", wantErr: "Failed to deserialize MsgPack: MsgPack decoding: trailing bytes"},
			// Rust: "|2+\n\n", "'\u2028  '\n" and "\"\\uFEFFa\"\n".
			"newline only":    {input: "a10a", want: "|+\n\n"},
			"line separator":  {input: "a3e280a8", want: "'\u2028'\n"},
			"byte order mark": {input: "a4efbbbf61", want: "\"\\uFEFF\\x61\"\n"},
		}
		for name, tt := range decodeTests {
			t.Run(name, func(t *testing.T) {
				input := mustHex(t, tt.input)
				got, err := MsgPack{}.Prettify(input, Metadata{})
				if tt.wantErr != "" {
					if err == nil || err.Error() != tt.wantErr {
						t.Fatalf("Prettify = %q, %v; want error %q", got, err, tt.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Fatalf("Prettify (-want +got):\n%s", diff)
				}
				data, err := MsgPack{}.Reencode(got, Metadata{})
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tt.input, hex.EncodeToString(data)); diff != "" {
					t.Fatalf("round trip (-original +reencoded):\n%s", diff)
				}
			})
		}
		encodeTests := map[string]struct {
			text    string
			want    string
			wantErr string
		}{
			// Rust reads every !!binary value as a string.
			"binary tag":         {text: "!!binary AQID", want: "c403010203"},
			"wrapped binary tag": {text: "!!binary |\n  AQ\n  ID\n", want: "c403010203"},
			"folded binary tag":  {text: "!!binary >\n  AQ\n  ID\n", want: "c403010203"},
			"invalid base64":     {text: "!!binary '@@'", wantErr: "Invalid YAML: invalid base64 in !!binary value"},
			// Whitespace is unwrapped only in block scalars; quoted text keeps
			// its bytes rather than encoding as empty binary.
			"quoted newline": {text: `!!binary "\n"`, wantErr: "Invalid YAML: invalid base64 in !!binary value"},
			"quoted space":   {text: `!!binary " "`, wantErr: "Invalid YAML: invalid base64 in !!binary value"},
			"quoted tab":     {text: `!!binary "\t"`, wantErr: "Invalid YAML: invalid base64 in !!binary value"},
		}
		for name, tt := range encodeTests {
			t.Run(name, func(t *testing.T) {
				data, err := MsgPack{}.Reencode(tt.text, Metadata{})
				if tt.wantErr != "" {
					if err == nil || err.Error() != tt.wantErr {
						t.Fatalf("Reencode = %x, %v; want error %q", data, err, tt.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tt.want, hex.EncodeToString(data)); diff != "" {
					t.Fatalf("Reencode (-want +got):\n%s", diff)
				}
			})
		}
	})
}

func TestMsgPackErrorsWrapCause(t *testing.T) {
	_, err := MsgPack{}.Prettify([]byte{0x92}, Metadata{})
	if err == nil || !strings.HasPrefix(err.Error(), "Failed to deserialize MsgPack: ") {
		t.Fatalf("truncated input error = %v", err)
	}
	budget := newViewBudget("MsgPack")
	budget.limits.Nodes = 1
	_, err = decodeMsgpackValue([]byte{0x91, 0x01}, budget)
	if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("node limit error = %v, want *LimitError", err)
	}
}

// FuzzMsgPack checks that rendered text reencodes to an equal value and that
// any YAML the view accepts encodes to well-formed MessagePack.
func FuzzMsgPack(f *testing.F) {
	f.Add(testMsgPack, testMsgPackYAML)
	for _, tt := range msgpackOracleDecode {
		data, err := hex.DecodeString(tt.input)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, tt.want)
	}
	for _, tt := range msgpackOracleEncode {
		f.Add([]byte{0xdd, 0xff, 0xff, 0xff, 0xff}, tt.text)
	}
	f.Fuzz(func(t *testing.T, data []byte, text string) {
		original := bytes.Clone(data)
		rendered, err := MsgPack{}.Prettify(data, Metadata{})
		if !bytes.Equal(data, original) {
			t.Fatal("input mutated")
		}
		if err == nil {
			reencoded, err := MsgPack{}.Reencode(rendered, Metadata{})
			if err != nil {
				t.Fatalf("Reencode(%q) of rendered %x: %v", rendered, data, err)
			}
			if diff := cmp.Diff(msgpackSemantic(t, data), msgpackSemantic(t, reencoded)); diff != "" {
				t.Fatalf("decode, reencode, decode of %x (-original +reencoded):\n%s", data, diff)
			}
		} else if !strings.HasPrefix(err.Error(), "Failed to deserialize MsgPack: ") && !strings.HasPrefix(err.Error(), "Failed to convert to YAML: ") {
			t.Fatalf("Prettify(%x) error %q has no view prefix", data, err)
		}
		encoded, err := MsgPack{}.Reencode(text, Metadata{})
		if err != nil {
			if !strings.HasPrefix(err.Error(), "Invalid YAML: ") && !strings.HasPrefix(err.Error(), "Failed to encode to MsgPack: ") {
				t.Fatalf("Reencode(%q) error %q has no view prefix", text, err)
			}
			return
		}
		if _, err := decodeMsgpackValue(encoded, newViewBudget("MsgPack")); err != nil {
			t.Fatalf("Reencode(%q) = %x, which does not decode: %v", text, encoded, err)
		}
	})
}
