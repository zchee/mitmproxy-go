// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// The literals are the fixtures of the pinned Rust view
// (mitmproxy-contentviews/src/protobuf/view_grpc.rs).
var (
	testGRPCYAML = "1: 150  # !sint: 75\n\n---\n\n1: 150  # !sint: 75\n"
	testGRPC     = []byte{
		0, 0, 0, 0, 3, 8, 150, 1,
		0, 0, 0, 0, 3, 8, 150, 1,
	}
	testGRPCGzip = []byte{
		1, 0, 0, 0, 23,
		31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 227, 152, 198, 8, 0, 160, 149, 78, 161, 3, 0, 0,
		0,
	}
	testGRPCDeflate = []byte{
		1, 0, 0, 0, 5,
		227, 152, 198, 8, 0,
	}
	testGRPCYAMLKnown = "example: 150\n\n---\n\nexample: 150\n"
)

// grpcMetadata carries the grpc-encoding header of the rendered message.
func grpcMetadata(encoding string) Metadata {
	message := &httpmsg.Message{}
	message.Headers.Set("grpc-encoding", encoding)
	return Metadata{HTTPMessage: message}
}

// grpcPathMetadata places the request path in the flow and marks the
// rendered message as the request or the response.
func grpcPathMetadata(path, definitions string, request bool) Metadata {
	f := &flow.HTTPFlow{Request: &httpmsg.Request{Path: path}, Response: &httpmsg.Response{}}
	metadata := Metadata{Flow: f, ProtobufDefinitions: protobufFixture(definitions)}
	if request {
		metadata.HTTPRequest = f.Request
	}
	return metadata
}

func TestGRPC(t *testing.T) {
	prettify := func(t *testing.T, data []byte, metadata Metadata, want string) {
		t.Helper()
		got, err := GRPC{}.Prettify(data, metadata)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("Prettify (-want +got):\n%s", diff)
		}
	}
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(t *testing.T){
			"test_empty":                 func(t *testing.T) { prettify(t, nil, Metadata{}, "") },
			"test_prettify_two_messages": func(t *testing.T) { prettify(t, testGRPC, Metadata{}, testGRPCYAML) },
			"test_prettify_gzip": func(t *testing.T) {
				prettify(t, testGRPCGzip, grpcMetadata("gzip"), "1: 150  # !sint: 75\n")
			},
			"test_prettify_deflate": func(t *testing.T) {
				prettify(t, testGRPCDeflate, grpcMetadata("deflate"), "1: 150  # !sint: 75\n")
			},
			"test_reencode_two_messages": func(t *testing.T) {
				got, err := GRPC{}.Reencode(testGRPCYAML, Metadata{})
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(hex.EncodeToString(testGRPC), hex.EncodeToString(got)); diff != "" {
					t.Fatalf("Reencode (-want +got):\n%s", diff)
				}
			},
			"test_render_priority": func(t *testing.T) {
				got := []float64{
					GRPC{}.RenderPriority(nil, Metadata{ContentType: "application/grpc"}),
					GRPC{}.RenderPriority(nil, Metadata{ContentType: "text/plain"}),
				}
				if diff := cmp.Diff([]float64{1, 0}, got); diff != "" {
					t.Fatalf("RenderPriority (-want +got):\n%s", diff)
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
		t.Run("existing_definition", func(t *testing.T) {
			tests := map[string]struct {
				metadata Metadata
				want     string
			}{
				"existing_proto":            {Metadata{ProtobufDefinitions: protobufFixture("simple.proto")}, testGRPCYAMLKnown},
				"existing_service_request":  {grpcPathMetadata("/Service/Method", "simple_service.proto", true), testGRPCYAML},
				"existing_service_response": {grpcPathMetadata("/Service/Method", "simple_service.proto", false), testGRPCYAMLKnown},
				"existing_package":          {grpcPathMetadata("/example.simple.Service/Method", "simple_package.proto", false), testGRPCYAMLKnown},
				"existing_nested":           {grpcPathMetadata("/example.nested.Service/Method", "nested.proto", false), testGRPCYAMLKnown},
				// Valid protobuf that does not fit the definition is rendered
				// without it.
				"existing_mismatch": {Metadata{ProtobufDefinitions: protobufFixture("mismatch.proto")}, testGRPCYAML},
			}
			for name, tt := range tests {
				t.Run(name, func(t *testing.T) { prettify(t, testGRPC, tt.metadata, tt.want) })
			}
		})
	})

	t.Run("view", func(t *testing.T) {
		if diff := cmp.Diff([]string{"gRPC", "yaml"}, []string{GRPC{}.Name(), GRPC{}.SyntaxHighlight()}); diff != "" {
			t.Fatalf("view identity (-want +got):\n%s", diff)
		}
		for _, contentType := range []string{"application/grpc+proto", "application/prpc"} {
			if got := (GRPC{}).RenderPriority(nil, Metadata{ContentType: contentType}); got != 1 {
				t.Fatalf("RenderPriority(%q) = %v, want 1", contentType, got)
			}
		}
	})

	t.Run("malformed", func(t *testing.T) {
		var corruptGzip bytes.Buffer
		writer := gzip.NewWriter(&corruptGzip)
		if _, err := writer.Write([]byte{8, 150, 1}); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		corrupt := corruptGzip.Bytes()
		corrupt[len(corrupt)-5] ^= 0xff
		frame := func(flag byte, payload []byte) []byte {
			return append([]byte{flag, 0, 0, 0, byte(len(payload))}, payload...)
		}
		tests := map[string]struct {
			data     []byte
			encoding string
			wantErr  string
		}{
			"flag is not a boolean":      {data: []byte{2, 0, 0, 0, 0}, wantErr: "invalid gRPC: first byte is not a boolean"},
			"truncated prefix":           {data: []byte{0, 0, 0}, wantErr: "invalid gRPC: not enough bytes"},
			"truncated body":             {data: []byte{0, 0, 0, 0, 3, 8, 150}, wantErr: "invalid gRPC: not enough data"},
			"later frame truncated":      {data: append(bytes.Clone(testGRPC), 0, 0, 0, 0, 9), wantErr: "invalid gRPC: not enough data"},
			"unsupported compression":    {data: frame(1, []byte{8, 1}), encoding: "br", wantErr: "unsupported gRPC compression"},
			"missing compression header": {data: frame(1, []byte{8, 1}), wantErr: "unsupported gRPC compression"},
			"corrupt gzip":               {data: frame(1, corrupt), encoding: "gzip", wantErr: "invalid gRPC compressed data"},
			"corrupt deflate":            {data: frame(1, []byte{0xff, 0xff, 0xff}), encoding: "deflate", wantErr: "invalid gRPC compressed data"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				got, err := GRPC{}.Prettify(tt.data, grpcMetadata(tt.encoding))
				if err == nil || got != "" || !strings.HasPrefix(err.Error(), tt.wantErr) {
					t.Fatalf("Prettify = %q, %v; want error %q and no partial output", got, err, tt.wantErr)
				}
			})
		}
		// A truncated stream fails the copy, and the decompressor's Close
		// returns the same sticky error; it is reported once.
		t.Run("truncated stream reports one error", func(t *testing.T) {
			payload := bytes.Repeat([]byte{8, 150, 1}, 64)
			var deflated bytes.Buffer
			deflater, err := flate.NewWriter(&deflated, flate.BestCompression)
			if err != nil {
				t.Fatal(err)
			}
			var gzipped bytes.Buffer
			gzipper := gzip.NewWriter(&gzipped)
			for _, w := range []io.WriteCloser{deflater, gzipper} {
				if _, err := w.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			tests := map[string]struct {
				data     []byte
				encoding string
			}{
				"deflate": {data: deflated.Bytes()[:deflated.Len()/2], encoding: "deflate"},
				"gzip":    {data: gzipped.Bytes()[:gzipped.Len()-4], encoding: "gzip"},
			}
			for name, tt := range tests {
				t.Run(name, func(t *testing.T) {
					got, err := GRPC{}.Prettify(frame(1, tt.data), grpcMetadata(tt.encoding))
					const want = "invalid gRPC compressed data: unexpected EOF"
					if err == nil || got != "" || err.Error() != want {
						t.Fatalf("Prettify = %q, %v; want error %q and no partial output", got, err, want)
					}
				})
			}
		})
		t.Run("identity compression", func(t *testing.T) {
			prettify(t, frame(1, []byte{8, 150, 1}), grpcMetadata("identity"), "1: 150  # !sint: 75\n")
		})
		t.Run("uncompressed ignores the header", func(t *testing.T) {
			prettify(t, frame(0, []byte{8, 150, 1}), grpcMetadata("br"), "1: 150  # !sint: 75\n")
		})
		t.Run("empty message", func(t *testing.T) {
			prettify(t, frame(0, nil), Metadata{}, "{}  # empty protobuf message")
		})
		// Expected results of the pinned Rust view (mitmproxy-rs 51fe2b7).
		reencodeTests := map[string]struct {
			text    string
			want    string
			wantErr string
		}{
			"no documents":         {text: "", wantErr: "YAML is not a mapping"},
			"comment only":         {text: "# c\n", wantErr: "YAML is not a mapping"},
			"empty document":       {text: "---\n", wantErr: "YAML is not a mapping"},
			"empty later document": {text: "1: 1\n---\n", wantErr: "YAML is not a mapping"},
			"two documents":        {text: "1: 1\n---\n2: 2\n", want: "0000000002080100000000021002"},
			"leading marker":       {text: "---\n1: 1\n", want: "00000000020801"},
			"document end":         {text: "1: 1\n...\n", want: "00000000020801"},
			"empty mapping":        {text: "{}", want: "0000000000"},
			"sequence":             {text: "- 1", wantErr: "YAML is not a mapping"},
			"invalid YAML":         {text: "@invalid", wantErr: "Invalid YAML: "},
		}
		for name, tt := range reencodeTests {
			t.Run("reencode/"+name, func(t *testing.T) {
				got, err := GRPC{}.Reencode(tt.text, Metadata{})
				if tt.wantErr != "" {
					if err == nil || got != nil || !strings.HasPrefix(err.Error(), tt.wantErr) {
						t.Fatalf("Reencode = %x, %v; want error %q and no partial output", got, err, tt.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tt.want, hex.EncodeToString(got)); diff != "" {
					t.Fatalf("Reencode (-want +got):\n%s", diff)
				}
			})
		}
	})
}

// testGRPCLimits holds the gRPC section of TestContentviewLimits.
func testGRPCLimits(t *testing.T) {
	tests := map[string]struct {
		data     []byte
		encoding string
		limits   func(*viewLimits)
		stage    string
		resource string
	}{
		// Each message expands within the limit, the two together do not.
		"decompressed bytes across messages": {
			data:     append(bytes.Clone(testGRPCDeflate), testGRPCDeflate...),
			encoding: "deflate",
			limits:   func(l *viewLimits) { l.DecompressedBytes = 5 },
			stage:    "gRPC decompression",
			resource: "decompressed bytes",
		},
		"messages share the node budget": {
			data:     bytes.Repeat(testGRPC, 4),
			limits:   func(l *viewLimits) { l.Nodes = 20 },
			resource: "logical nodes",
		},
		"input bytes": {
			data:     testGRPC,
			limits:   func(l *viewLimits) { l.InputBytes = 15 },
			stage:    "gRPC framing",
			resource: "input bytes",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			budget := limitedBudget("gRPC", tt.limits)
			_, err := prettifyGRPC(tt.data, tt.encoding, nil, budget)
			limit, ok := errors.AsType[*LimitError](err)
			if !ok {
				t.Fatalf("error %v is not a *LimitError", err)
			}
			if limit.View != "gRPC" || limit.Resource != tt.resource || tt.stage != "" && limit.Stage != tt.stage {
				t.Fatalf("refusal %+v, want stage %q resource %q", limit, tt.stage, tt.resource)
			}
		})
	}
	t.Run("one message alone fits", func(t *testing.T) {
		budget := limitedBudget("gRPC", func(l *viewLimits) { l.DecompressedBytes = 5 })
		if _, err := prettifyGRPC(testGRPCDeflate, "deflate", nil, budget); err != nil {
			t.Fatal(err)
		}
		if budget.decompressed != 3 {
			t.Fatalf("decompressed counter = %d, want 3", budget.decompressed)
		}
	})
	t.Run("reencode output", func(t *testing.T) {
		budget := limitedBudget("gRPC", func(l *viewLimits) { l.OutputBytes = 15 })
		_, err := reencodeGRPC(testGRPCYAML, nil, budget)
		if limit, ok := errors.AsType[*LimitError](err); !ok || limit.Resource != "output bytes" {
			t.Fatalf("error %v, want an output refusal", err)
		}
	})
}

// FuzzGRPC checks that rendering never panics or returns partial output on
// failure, and that encoded documents frame back to the same rendering.
func FuzzGRPC(f *testing.F) {
	for _, seed := range []struct {
		data     []byte
		encoding string
	}{
		{testGRPC, ""},
		{testGRPCGzip, "gzip"},
		{testGRPCDeflate, "deflate"},
		{[]byte{1, 0, 0, 0, 5, 0xff, 0xff, 0xff, 0xff, 0xff}, "deflate"},
		{[]byte{0, 0xff, 0xff, 0xff, 0xff}, ""},
		{[]byte{2}, ""},
	} {
		f.Add(seed.data, seed.encoding)
	}
	f.Fuzz(func(t *testing.T, data []byte, encoding string) {
		original := bytes.Clone(data)
		text, err := GRPC{}.Prettify(data, grpcMetadata(encoding))
		if !bytes.Equal(data, original) {
			t.Fatal("input mutated")
		}
		if err != nil {
			if text != "" {
				t.Fatalf("partial output %q with error %v", text, err)
			}
			return
		}
		encoded, err := GRPC{}.Reencode(text, Metadata{})
		if err != nil {
			return
		}
		if _, err := (GRPC{}).Prettify(encoded, Metadata{}); err != nil {
			t.Fatalf("Prettify(Reencode(%q)) = %x: %v", text, encoded, err)
		}
	})
}
