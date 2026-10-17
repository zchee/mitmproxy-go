// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// protobufRoundTrips are the literal vectors of the pinned Rust view
// (mitmproxy-contentviews/src/protobuf/view_protobuf.rs, test_roundtrip!).
var protobufRoundTrips = map[string]struct {
	proto []byte
	yaml  string
}{
	"varint":                    {[]byte("\x08\x96\x01"), "1: 150  # !sint: 75\n"},
	"varint_zigzag_negative":    {[]byte("\x08\x0B"), "1: 11  # !sint: -6\n"},
	"varint_int64_negative":     {[]byte("\x08\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01"), "1: -2  # u64: 18446744073709551614\n"},
	"binary":                    {[]byte("\x32\x03\x01\x02\x03"), "6: !binary '010203'\n"},
	"string":                    {[]byte("\x0A\x05\x68\x65\x6C\x6C\x6F"), "1: hello\n"},
	"nested":                    {[]byte("\x2A\x02\x08\x2A"), "5:\n  1: 42  # !sint: 21\n"},
	"nested_twice":              {[]byte("\x2A\x04\x2A\x02\x08\x2A"), "5:\n  5:\n    1: 42  # !sint: 21\n"},
	"fixed64":                   {[]byte("\x19\x00\x00\x00\x00\x00\x00\xF0\xBF"), "3: !fixed64 -1.0  # u64: 13830554455654793216, i64: -4616189618054758400\n"},
	"fixed64_positive":          {[]byte("\x19\x6E\x86\x1B\xF0\xF9\x21\x09\x40"), "3: !fixed64 3.14159  # u64: 4614256650576692846\n"},
	"fixed64_no_float":          {[]byte("\x19\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"), "3: !fixed64 -1  # u64: 18446744073709551615\n"},
	"fixed64_positive_no_float": {[]byte("\x19\x01\x00\x00\x00\x00\x00\xF8\x7F"), "3: !fixed64 9221120237041090561\n"},
	"fixed32":                   {[]byte("\x15\x00\x00\x80\xBF"), "2: !fixed32 -1.0  # u32: 3212836864, i32: -1082130432\n"},
	"fixed32_positive":          {[]byte("\x15\xD0\x0F\x49\x40"), "2: !fixed32 3.14159  # u32: 1078530000\n"},
	"fixed32_no_float":          {[]byte("\x15\xFF\xFF\xFF\xFF"), "2: !fixed32 -1  # u32: 4294967295\n"},
	"fixed32_positive_no_float": {[]byte("\x15\x01\x00\xC0\x7F"), "2: !fixed32 2143289345\n"},
	"repeated_packed":           {[]byte("\x32\x06\x03\x8E\x02\x9E\xA7\x05"), "6: !binary 038e029ea705\n"},
	"repeated_varint":           {[]byte("\x08\x01\x08\x02\x08\x03"), "1:\n- 1  # !sint: -1\n- 2  # !sint: 1\n- 3  # !sint: -2\n"},
}

// protobufFixture is a schema from the Rust view's test data, kept in this
// repository under testdata/mitmproxy-rs.
func protobufFixture(name string) string {
	return filepath.Join("..", "testdata", "mitmproxy-rs", "contentviews", "protobuf", name)
}

func TestProtobufRoundTrip(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		for name, tt := range protobufRoundTrips {
			t.Run(name, func(t *testing.T) {
				t.Run("prettify", func(t *testing.T) {
					input := bytes.Clone(tt.proto)
					got, err := Protobuf{}.Prettify(input, Metadata{})
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(tt.yaml, got); diff != "" {
						t.Fatalf("Prettify(%x) (-want +got):\n%s", tt.proto, diff)
					}
					if !bytes.Equal(input, tt.proto) {
						t.Fatal("input mutated")
					}
				})
				t.Run("reencode", func(t *testing.T) {
					got, err := Protobuf{}.Reencode(tt.yaml, Metadata{})
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(hex.EncodeToString(tt.proto), hex.EncodeToString(got)); diff != "" {
						t.Fatalf("Reencode(%q) (-want +got):\n%s", tt.yaml, diff)
					}
				})
			})
		}
		t.Run("direct", func(t *testing.T) {
			tests := map[string]func(t *testing.T){
				"test_invalid_protobuf": func(t *testing.T) {
					if got, err := (Protobuf{}).Prettify([]byte{0xff, 0xff}, Metadata{}); err == nil {
						t.Fatalf("Prettify(ffff) = %q, want an error", got)
					}
				},
				"test_no_crash": func(t *testing.T) {
					input := []byte("\n\x13gRPC testing server\x12\x07\n\x05Index\x12\x07\n\x05Empty\x12\x0c\n\nDummyUnary\x12\x0f\n\rSpecificError\x12\r\n\x0bRandomError\x12\x0e\n\x0cHeadersUnary\x12\x11\n\x0fNoResponseUnary")
					want := "1: gRPC testing server\n2:\n- 1: Index\n- 1: Empty\n- 1: DummyUnary\n- 1: SpecificError\n- 1: RandomError\n- 1: HeadersUnary\n- 1: NoResponseUnary\n"
					got, err := Protobuf{}.Prettify(input, Metadata{})
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(want, got); diff != "" {
						t.Fatalf("Prettify (-want +got):\n%s", diff)
					}
				},
				"test_empty_protobuf": func(t *testing.T) {
					got, err := Protobuf{}.Prettify(nil, Metadata{})
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff("{}  # empty protobuf message", got); diff != "" {
						t.Fatalf("Prettify (-want +got):\n%s", diff)
					}
				},
			}
			for name, test := range tests {
				t.Run(name, test)
			}
		})
	})
}

func TestProtobufDefinitions(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("existing_definition", func(t *testing.T) {
			const varintPrettyYAML = "example: 150\n"
			metadata := Metadata{ProtobufDefinitions: protobufFixture("simple.proto")}
			tests := map[string]func(t *testing.T){
				"prettify": func(t *testing.T) {
					got, err := Protobuf{}.Prettify(protobufRoundTrips["varint"].proto, metadata)
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(varintPrettyYAML, got); diff != "" {
						t.Fatalf("Prettify (-want +got):\n%s", diff)
					}
				},
				// Wire data that is valid protobuf but does not fit the
				// definition is rendered without it.
				"prettify_mismatch": func(t *testing.T) {
					got, err := Protobuf{}.Prettify(protobufRoundTrips["string"].proto, metadata)
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(protobufRoundTrips["string"].yaml, got); diff != "" {
						t.Fatalf("Prettify (-want +got):\n%s", diff)
					}
				},
				"reencode": func(t *testing.T) {
					got, err := Protobuf{}.Reencode(varintPrettyYAML, metadata)
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(hex.EncodeToString(protobufRoundTrips["varint"].proto), hex.EncodeToString(got)); diff != "" {
						t.Fatalf("Reencode (-want +got):\n%s", diff)
					}
				},
				"reencode_mismatch": func(t *testing.T) {
					got, err := Protobuf{}.Reencode("example: hello", metadata)
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(hex.EncodeToString(protobufRoundTrips["string"].proto), hex.EncodeToString(got)); diff != "" {
						t.Fatalf("Reencode (-want +got):\n%s", diff)
					}
				},
			}
			for name, test := range tests {
				t.Run(name, test)
			}
		})
	})

	// A proto2 group is framed by start and end group tags on the wire, not
	// by a length, so a schema that declares one must parse the group body.
	t.Run("groups", func(t *testing.T) {
		const schema = `syntax = "proto2";

message Outer {
  optional group Item = 1 {
    optional int32 id = 2;
    optional group Inner = 6 {
      optional string label = 7;
    }
  }
  repeated group Entry = 3 {
    optional string name = 4;
  }
  optional int32 tail = 5;
}
`
		path := filepath.Join(t.TempDir(), "groups.proto")
		if err := os.WriteFile(path, []byte(schema), 0o600); err != nil {
			t.Fatal(err)
		}
		metadata := Metadata{ProtobufDefinitions: path}
		// item {id: 7, inner {label: "x"}}, entry {name: "a"}, entry {name: "b"}, tail: 9.
		full := []byte("\x0b\x10\x07\x33\x3a\x01x\x34\x0c\x1b\x22\x01a\x1c\x1b\x22\x01b\x1c\x28\x09")
		tests := map[string]struct {
			proto   []byte
			want    string
			wantErr string
		}{
			"success: singular, nested and repeated groups render by name": {
				proto: full,
				want:  "item:\n  id: 7\n  inner:\n    label: x\nentry:\n- name: a\n- name: b\ntail: 9\n",
			},
			"success: an empty group renders as an empty mapping": {
				proto: []byte("\x0b\x0c\x28\x09"),
				want:  "item: {}\ntail: 9\n",
			},
			"success: a group field sent length-delimited falls back to the schema-less rendering": {
				proto: []byte("\x0a\x02\x10\x07"),
				want:  "1:\n  2: 7  # !sint: -4\n",
			},
			"error: an unterminated group": {
				proto:   []byte("\x0b\x10\x07"),
				wantErr: "Error parsing protobuf: unterminated protobuf group",
			},
			"error: a group truncated inside a field value": {
				proto:   []byte("\x0b\x10"),
				wantErr: "Error parsing protobuf: invalid protobuf group value: unexpected EOF",
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				got, err := Protobuf{}.Prettify(tt.proto, metadata)
				if tt.wantErr != "" {
					if err == nil || err.Error() != tt.wantErr {
						t.Fatalf("Prettify error = %v, want %q (text %q)", err, tt.wantErr, got)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Fatalf("Prettify (-want +got):\n%s", diff)
				}
			})
		}

		reencodes := map[string]struct {
			yaml    string
			want    []byte
			wantErr string
		}{
			"success: nested singular groups round-trip": {
				yaml: "item:\n  id: 7\n  inner:\n    label: x\ntail: 9\n",
				want: []byte("\x0b\x10\x07\x33\x3a\x01x\x34\x0c\x28\x09"),
			},
			"success: an empty group keeps its start and end tags": {
				yaml: "item: {}\n",
				want: []byte("\x0b\x0c"),
			},
			// Elements of a repeated message field are encoded without
			// their definition, as the Rust view does, so field names
			// inside them do not resolve.
			"error: repeated group elements are encoded without the definition": {
				yaml:    "entry:\n- name: a\n",
				wantErr: "unknown protobuf field key",
			},
		}
		for name, tt := range reencodes {
			t.Run(name, func(t *testing.T) {
				got, err := Protobuf{}.Reencode(tt.yaml, metadata)
				if tt.wantErr != "" {
					if err == nil || err.Error() != tt.wantErr {
						t.Fatalf("Reencode error = %v, want %q", err, tt.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(hex.EncodeToString(tt.want), hex.EncodeToString(got)); diff != "" {
					t.Fatalf("Reencode (-want +got):\n%s", diff)
				}
				// The encoding renders back to the same text.
				text, err := Protobuf{}.Prettify(got, metadata)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tt.yaml, text); diff != "" {
					t.Fatalf("Prettify(Reencode) (-want +got):\n%s", diff)
				}
			})
		}
	})

	t.Run("fixtures", func(t *testing.T) {
		// describe lists "message.field kind" for every field of every message
		// reachable from the file's top-level messages, in declaration order.
		describe := func(message protoreflect.MessageDescriptor) []string {
			var out []string
			var walk func(protoreflect.MessageDescriptor)
			walk = func(message protoreflect.MessageDescriptor) {
				fields := message.Fields()
				for i := range fields.Len() {
					field := fields.Get(i)
					out = append(out, string(message.FullName())+"."+string(field.Name())+" "+field.Kind().String())
				}
				nested := message.Messages()
				for i := range nested.Len() {
					walk(nested.Get(i))
				}
			}
			walk(message)
			return out
		}
		tests := map[string]struct {
			messages []string
			services []string
			fields   []string
		}{
			"mismatch.proto": {
				messages: []string{"TestMessage"},
				fields:   []string{"TestMessage.example string"},
			},
			"nested.proto": {
				messages: []string{"example.nested.Empty", "example.nested.Response"},
				services: []string{"example.nested.Service.Method(example.nested.Empty) example.nested.Response"},
				fields:   []string{"example.nested.Response.example int32", "example.nested.Response.nested message", "example.nested.Response.Nested.example int32"},
			},
			"simple.proto": {
				messages: []string{"TestMessage"},
				fields:   []string{"TestMessage.example int32"},
			},
			"simple_package.proto": {
				messages: []string{"example.simple.Empty", "example.simple.Response"},
				services: []string{"example.simple.Other.Method(example.simple.Empty) example.simple.Response", "example.simple.Service.Method(example.simple.Empty) example.simple.Response"},
				fields:   []string{"example.simple.Response.example int32"},
			},
			"simple_service.proto": {
				messages: []string{"Empty", "Response"},
				services: []string{"Other.Method(Empty) Response", "Service.Method(Empty) Response"},
				fields:   []string{"Response.example int32"},
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				schema, err := loadProtobufSchema(t.Context(), []string{protobufFixture(name)}, schemaLimits{}, newViewBudget("Protobuf"))
				if err != nil {
					t.Fatal(err)
				}
				if len(schema.files) != 1 {
					t.Fatalf("loaded %d files, want 1", len(schema.files))
				}
				file := schema.files[0]
				var messages, services, fields []string
				for i := range file.Messages().Len() {
					message := file.Messages().Get(i)
					messages = append(messages, string(message.FullName()))
					fields = append(fields, describe(message)...)
				}
				for i := range file.Services().Len() {
					service := file.Services().Get(i)
					for j := range service.Methods().Len() {
						method := service.Methods().Get(j)
						services = append(services, string(service.FullName())+"."+string(method.Name())+"("+string(method.Input().FullName())+") "+string(method.Output().FullName()))
					}
				}
				got := map[string][]string{"messages": messages, "services": services, "fields": fields}
				want := map[string][]string{"messages": tt.messages, "services": tt.services, "fields": tt.fields}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Fatalf("descriptors (-want +got):\n%s", diff)
				}
			})
		}
	})
}

func TestProtobufView(t *testing.T) {
	view := Protobuf{}
	if diff := cmp.Diff([]string{"Protobuf", "yaml"}, []string{view.Name(), view.SyntaxHighlight()}); diff != "" {
		t.Fatalf("view identity (-want +got):\n%s", diff)
	}
	tests := map[string]struct {
		contentType string
		want        float64
	}{
		"x-protobuf":    {"application/x-protobuf", 1},
		"x-protobuffer": {"application/x-protobuffer", 1},
		"grpc":          {"application/grpc", 0},
		"none":          {"", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := view.RenderPriority(nil, Metadata{ContentType: tt.contentType}); got != tt.want {
				t.Fatalf("RenderPriority(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
	if _, err := view.Prettify([]byte{8, 1}, Metadata{ProtobufDefinitions: protobufFixture("missing.proto")}); err == nil || !strings.HasPrefix(err.Error(), "failed to parse proto file(s): ") {
		t.Fatalf("missing definitions error = %v", err)
	}
}

// TestProtobufSelection renders through the metadata-aware entry point, so
// the request path and the rendered message's direction choose the message.
func TestProtobufSelection(t *testing.T) {
	newFlow := func(path string) *flow.HTTPFlow {
		request := &httpmsg.Request{Path: path, RawContent: protobufRoundTrips["varint"].proto}
		request.Headers.Set("content-type", "application/x-protobuf")
		response := &httpmsg.Response{RawContent: protobufRoundTrips["varint"].proto}
		response.Headers.Set("content-type", "application/x-protobuf")
		return &flow.HTTPFlow{Request: request, Response: response}
	}
	const (
		empty    = "1: 150  # !sint: 75\n"
		response = "example: 150\n"
	)
	tests := map[string]struct {
		definitions  string
		path         string
		wantRequest  string
		wantResponse string
	}{
		"service method":          {"simple_service.proto", "/Service/Method", empty, response},
		"query falls back":        {"simple_service.proto", "/Service/Method?x=1", empty, response},
		"unknown method":          {"simple_service.proto", "/Service/Missing", empty, response},
		"package service method":  {"simple_package.proto", "/example.simple.Service/Method", empty, response},
		"nested package":          {"nested.proto", "/example.nested.Service/Method", empty, response},
		"message named by method": {"simple.proto", "/Any/TestMessage", "example: 150\n", "example: 150\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFlow(tt.path)
			metadata := Metadata{Flow: f, ProtobufDefinitions: protobufFixture(tt.definitions)}
			for _, message := range []struct {
				name    string
				message any
				want    string
			}{{"request", f.Request, tt.wantRequest}, {"response", f.Response, tt.wantResponse}} {
				got := PrettifyMessageWithMetadata(message.message, metadata, "Protobuf", nil, 0)
				if got.Err != nil {
					t.Fatalf("%s: %v", message.name, got.Err)
				}
				if diff := cmp.Diff(message.want, got.Text); diff != "" {
					t.Fatalf("%s (-want +got):\n%s", message.name, diff)
				}
			}
		})
	}
}

// FuzzProtobuf checks that rendering never panics and that renderings are
// stable once encoded: groups are skipped on rendering, so the first
// encoding may normalize the wire data, but encoding the rendering of that
// encoding again must reproduce the same text.
func FuzzProtobuf(f *testing.F) {
	for _, tt := range protobufRoundTrips {
		f.Add(tt.proto)
	}
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0x0b, 0x13, 0x14, 0x0c})
	f.Add([]byte{0x0a, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00})
	f.Add([]byte("\n\x13gRPC testing server\x12\x07\n\x05Index"))
	f.Fuzz(func(t *testing.T, data []byte) {
		original := bytes.Clone(data)
		text, err := Protobuf{}.Prettify(data, Metadata{})
		if !bytes.Equal(data, original) {
			t.Fatal("input mutated")
		}
		if err != nil {
			return
		}
		for round := range 2 {
			encoded, err := Protobuf{}.Reencode(text, Metadata{})
			if err != nil || len(encoded) == 0 {
				// Renderings such as inf.0 do not read back as numbers
				// upstream either, and skipped groups encode as no bytes.
				return
			}
			again, err := Protobuf{}.Prettify(encoded, Metadata{})
			if err != nil {
				t.Fatalf("Prettify(Reencode(%q)) = %x: %v", text, encoded, err)
			}
			if round == 1 {
				if diff := cmp.Diff(text, again); diff != "" {
					t.Fatalf("rendering of %x is not stable (-first +second):\n%s", data, diff)
				}
			}
			text = again
		}
	})
}

// FuzzProtobufReencode checks that any YAML the view accepts encodes to
// well-formed protobuf wire data.
func FuzzProtobufReencode(f *testing.F) {
	for _, tt := range protobufRoundTrips {
		f.Add(tt.yaml)
	}
	for _, tt := range protobufSchemaOracle {
		f.Add(tt.text)
	}
	for _, text := range []string{"1: !fixed32 .inf", "1: !binary 0102", "1: !sint -3", "a: 1\na: 2\n", "@invalid", "1: [1, {2: x}]"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		encoded, err := Protobuf{}.Reencode(text, Metadata{})
		if err != nil {
			return
		}
		verify := func(data []byte) {
			for len(data) != 0 {
				number, typ, n := protowire.ConsumeTag(data)
				if n < 0 || !number.IsValid() {
					t.Fatalf("Reencode(%q) = %x: invalid tag", text, encoded)
				}
				data = data[n:]
				n = protowire.ConsumeFieldValue(number, typ, data)
				if n < 0 || typ == protowire.StartGroupType || typ == protowire.EndGroupType {
					t.Fatalf("Reencode(%q) = %x: invalid value", text, encoded)
				}
				data = data[n:]
			}
		}
		verify(encoded)
	})
}
