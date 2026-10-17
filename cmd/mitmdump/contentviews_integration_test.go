// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration

package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// catalogProto is the schema the protobuf_definitions cases load. The
// request paths name its service method, so the views resolve Item for the
// request and the response.
const catalogProto = `syntax = "proto3";
package cli;
message Item {
  int32 id = 1;
  string name = 2;
}
service Catalog {
  rpc Get(Item) returns (Item);
}
`

// itemMessage encodes an Item on the wire: field 1 as a varint and field 2
// as a length-delimited string.
func itemMessage(id uint64, name string) []byte {
	message := protowire.AppendTag(nil, 1, protowire.VarintType)
	message = protowire.AppendVarint(message, id)
	message = protowire.AppendTag(message, 2, protowire.BytesType)
	return protowire.AppendString(message, name)
}

// grpcFrame wraps one uncompressed message in the five-byte gRPC prefix.
func grpcFrame(message []byte) []byte {
	frame := make([]byte, 5, 5+len(message))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(message)))
	return append(frame, message...)
}

// httpExchange returns a POST to path whose request and response bodies
// carry the content type.
func httpExchange(path, contentType string, request, response []byte) *flow.HTTPFlow {
	headers := func(body []byte) httpmsg.Headers {
		return httpmsg.Headers{
			{Name: []byte("content-type"), Value: []byte(contentType)},
			{Name: []byte("content-length"), Value: []byte(strconv.Itoa(len(body)))},
		}
	}
	f := testflow.TFlow(testflow.WithResponse)
	f.Request.Method = "POST"
	f.Request.Path = path
	f.Request.Headers = headers(request)
	f.Request.RawContent = request
	f.Response.Headers = headers(response)
	f.Response.RawContent = response
	return f
}

func zipArchive(t *testing.T, names ...string) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, name := range names {
		w, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

// msgpackBody is {"name": "mitm", "tags": [1, 2]} in MessagePack.
var msgpackBody = []byte{0x82, 0xa4, 'n', 'a', 'm', 'e', 0xa4, 'm', 'i', 't', 'm', 0xa4, 't', 'a', 'g', 's', 0x92, 0x01, 0x02}

// http3Headers is the HEADERS frame vector of upstream's test_view_http3.
const http3Headers = "011d0000d1c1d7508a089d5c0b8170dc780f035f508825b650c3abbcdae0dd"

// saveFlows writes the flows with the production flow writer and returns
// the file the binary reads.
func saveFlows(t *testing.T, flows ...flow.Flow) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flows.mitm")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := flowio.NewWriter(file)
	for _, f := range flows {
		if err := writer.Add(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// block is the dumper's rendering of content lines: each line indented by
// four spaces, framed by the line breaks around it.
func block(lines ...string) string {
	return "\n    " + strings.Join(lines, "\n    ") + "\n"
}

var terminalEscape = regexp.MustCompile("\x1b\\[")

// runDump runs the built binary over the saved flows and checks what every
// content-view run shares: exit status 0, nothing on stderr and plain pipe
// output without terminal escape sequences.
func runDump(t *testing.T, path, detail string, extra ...string) string {
	t.Helper()
	args := append([]string{"-n", "-r", path, "--flow-detail", detail}, extra...)
	out, stderr, code := goRun(t, args...)
	if code != 0 || stderr != "" {
		t.Fatalf("mitmdump %q: exit=%d stderr=%q\nstdout:\n%s", args, code, stderr, out)
	}
	if terminalEscape.MatchString(out) {
		t.Fatalf("pipe output carries terminal escape sequences:\n%q", out)
	}
	return out
}

func checkBlocks(t *testing.T, out string, want, absent []string) {
	t.Helper()
	for _, b := range want {
		if !strings.Contains(out, b) {
			t.Errorf("stdout lacks the block %q", b)
		}
	}
	for _, b := range absent {
		if strings.Contains(out, b) {
			t.Errorf("stdout unexpectedly contains %q", b)
		}
	}
	if t.Failed() {
		t.Logf("stdout:\n%s", out)
	}
}

func TestContentviewsCLI(t *testing.T) {
	t.Run("views", func(t *testing.T) {
		wbxmlBody, err := os.ReadFile(testutil.FixturePath(t, "mitmproxy/contentviews/test_wbxml_data/data.wbxml"))
		if err != nil {
			t.Fatal(err)
		}
		// The pinned Python view's formatting of the same body.
		wbxmlFormatted, err := os.ReadFile(testutil.FixturePath(t, "mitmproxy/contentviews/test_wbxml_data/data-formatted.wbxml"))
		if err != nil {
			t.Fatal(err)
		}
		tests := map[string]struct {
			flows  func(t *testing.T) []flow.Flow
			args   []string
			want   []string
			absent []string
		}{
			"auto selects MsgPack": {
				flows: func(*testing.T) []flow.Flow {
					return []flow.Flow{httpExchange("/msgpack", "application/msgpack", msgpackBody, msgpackBody)}
				},
				want: []string{block("name: mitm", "tags:", "- 1", "- 2")},
			},
			"explicit hex dump overrides MsgPack": {
				flows: func(*testing.T) []flow.Flow {
					return []flow.Flow{httpExchange("/msgpack", "application/msgpack", msgpackBody, msgpackBody)}
				},
				args:   []string{"--set", "dumper_default_contentview=hex dump"},
				want:   []string{block("0000:   82 a4 6e 61  6d 65 a4 6d  69 74 6d a4  74 61 67 73   ..name.mitm.tags", "0010:   92 01 02                                             ...")},
				absent: []string{"name: mitm"},
			},
			"auto selects Protobuf": {
				flows: func(*testing.T) []flow.Flow {
					return []flow.Flow{httpExchange("/cli.Catalog/Get", "application/x-protobuf", itemMessage(42, "widget"), itemMessage(7, "gear"))}
				},
				want: []string{block("1: 42  # !sint: 21", "2: widget"), block("1: 7  # !sint: -4", "2: gear")},
			},
			"auto selects gRPC": {
				flows: func(*testing.T) []flow.Flow {
					return []flow.Flow{httpExchange("/cli.Catalog/Get", "application/grpc", grpcFrame(itemMessage(42, "widget")), grpcFrame(itemMessage(7, "gear")))}
				},
				want: []string{block("1: 42  # !sint: 21", "2: widget"), block("1: 7  # !sint: -4", "2: gear")},
			},
			"auto selects GraphQL over JSON": {
				flows: func(*testing.T) []flow.Flow {
					return []flow.Flow{httpExchange("/graphql", "application/json", []byte(`{"query":"query {\n  hero\n}","variables":{}}`), []byte(`{"data":{"hero":"R2"}}`))}
				},
				want: []string{
					block("{", `  "query": "...",`, `  "variables": {}`, "}", "---", "query {", "  hero", "}"),
					// The response is not a GraphQL query, so the JSON view keeps it.
					block("{", `    "data": {`, `        "hero": "R2"`, "    }", "}"),
				},
			},
			"auto selects WBXML": {
				flows: func(*testing.T) []flow.Flow {
					return []flow.Flow{httpExchange("/Microsoft-Server-ActiveSync", "application/vnd.ms-sync.wbxml", wbxmlBody, wbxmlBody)}
				},
				want: []string{block(strings.Split(strings.TrimRight(string(wbxmlFormatted), "\n"), "\n")...)},
			},
			"auto selects ZIP": {
				flows: func(t *testing.T) []flow.Flow {
					body := zipArchive(t, "a.txt", "dir/b.txt")
					return []flow.Flow{httpExchange("/archive", "application/zip", body, body)}
				},
				want: []string{block("- a.txt", "- dir/b.txt")},
			},
			"auto selects Socket.IO for WebSocket messages": {
				flows: func(*testing.T) []flow.Flow {
					f := testflow.TWebSocketFlow()
					f.Request.Path = "/socket.io/?EIO=4&transport=websocket"
					f.WebSocket.Messages = []*websocket.Message{
						{Type: websocket.OpText, FromClient: true, Content: []byte(`42["chat","hi"]`), Timestamp: 946681203},
						{Type: websocket.OpText, FromClient: false, Content: []byte(`0{"sid":"abc"}`), Timestamp: 946681204},
					}
					return []flow.Flow{f}
				},
				want: []string{block(`SocketIO.EVENT ["chat","hi"]`), block(`EngineIO.OPEN {"sid":"abc"}`)},
			},
			"auto selects HTTP/3 frames for an h3 TCP stream": {
				flows: func(t *testing.T) []flow.Flow {
					data, err := hex.DecodeString(http3Headers)
					if err != nil {
						t.Fatal(err)
					}
					f := testflow.TTCPFlow()
					f.ClientConn.ALPN = []byte("h3")
					f.Messages = []*tcp.Message{{FromClient: true, Content: data, Timestamp: 946681204.2}}
					return []flow.Flow{f}
				},
				want: []string{block("HEADERS Frame", ":method: GET", ":path: /", ":scheme: https", ":authority: 127.0.0.1:8080", "user-agent: curl/7.85.0", "accept: */*")},
			},
			"explicit MQTT for TCP messages": {
				flows: func(*testing.T) []flow.Flow {
					f := testflow.TTCPFlow()
					f.Messages = []*tcp.Message{{FromClient: true, Content: []byte{0x30, 0x07, 0x00, 0x03, 't', 'o', 'p', 'h', 'i'}, Timestamp: 946681204.2}}
					return []flow.Flow{f}
				},
				args: []string{"--set", "dumper_default_contentview=mqtt"},
				want: []string{block("[PUBLISH] 'hi' to topic 'top'")},
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				path := saveFlows(t, tt.flows(t)...)
				for _, detail := range []string{"3", "4"} {
					out := runDump(t, path, detail, tt.args...)
					checkBlocks(t, out, tt.want, tt.absent)
				}
			})
		}
	})

	t.Run("protobuf definitions", func(t *testing.T) {
		withSchema := []string{block("id: 42", "name: widget"), block("id: 7", "name: gear")}
		withoutSchema := []string{block("1: 42  # !sint: 21", "2: widget")}
		tests := map[string]struct {
			contentType string
			body        func([]byte) []byte
			folder      bool
		}{
			"Protobuf with a definitions file":   {contentType: "application/x-protobuf", body: func(b []byte) []byte { return b }},
			"Protobuf with a definitions folder": {contentType: "application/x-protobuf", body: func(b []byte) []byte { return b }, folder: true},
			"gRPC with a definitions file":       {contentType: "application/grpc", body: grpcFrame},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				path := saveFlows(t, httpExchange("/cli.Catalog/Get", tt.contentType, tt.body(itemMessage(42, "widget")), tt.body(itemMessage(7, "gear"))))
				dir := t.TempDir()
				schema := filepath.Join(dir, "catalog.proto")
				if err := os.WriteFile(schema, []byte(catalogProto), 0o600); err != nil {
					t.Fatal(err)
				}
				definitions := schema
				if tt.folder {
					definitions = dir
				}
				out := runDump(t, path, "3", "--set", "protobuf_definitions="+definitions)
				checkBlocks(t, out, withSchema, withoutSchema)

				// An edited schema is read again on the next run: the renamed
				// field shows its new name.
				edited := strings.Replace(catalogProto, "int32 id = 1;", "int32 item_id = 1;", 1)
				if err := os.WriteFile(schema, []byte(edited), 0o600); err != nil {
					t.Fatal(err)
				}
				out = runDump(t, path, "3", "--set", "protobuf_definitions="+definitions)
				checkBlocks(t, out, []string{block("item_id: 42", "name: widget"), block("item_id: 7", "name: gear")}, []string{"    id: 42\n"})
			})
		}
	})

	t.Run("detail levels", func(t *testing.T) {
		body := zipArchive(t, "a.txt", "b.txt", "c.txt")
		path := saveFlows(t, httpExchange("/archive", "application/zip", body, body))
		tests := map[string]struct {
			detail string
			want   []string
			absent []string
		}{
			"flow_detail 3 marks content beyond the line cutoff": {
				detail: "3",
				want:   []string{block("- a.txt", "- b.txt", "- c.txt") + "    (cut off)\n"},
			},
			"flow_detail 4 shows content without a cutoff": {
				detail: "4",
				want:   []string{block("- a.txt", "- b.txt", "- c.txt")},
				absent: []string{"(cut off)"},
			},
			"flow_detail 2 shows no content": {
				detail: "2",
				absent: []string{"- a.txt", "(cut off)"},
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				out := runDump(t, path, tt.detail, "--set", "content_view_lines_cutoff=1")
				checkBlocks(t, out, tt.want, tt.absent)
			})
		}
	})

	t.Run("view choices", func(t *testing.T) {
		out, stderr, code := goRun(t, "--options")
		if code != 0 || stderr != "" {
			t.Fatalf("--options: exit=%d stderr=%q", code, stderr)
		}
		// The option's comment lists its choices before the option line.
		head, _, found := strings.Cut(out, "\ndumper_default_contentview: auto\n")
		if !found {
			t.Fatalf("option listing lacks the default dumper_default_contentview: auto:\n%s", out)
		}
		comment := head[strings.LastIndex(head, "\n\n")+2:]
		_, values, found := strings.Cut(strings.ReplaceAll(strings.ReplaceAll(comment, "\n# ", " "), "# ", ""), "Valid values are ")
		if !found {
			t.Fatalf("dumper_default_contentview comment lacks its valid values:\n%s", comment)
		}
		var listed []string
		for _, value := range strings.Split(strings.TrimSuffix(strings.TrimSpace(values), "."), ", ") {
			listed = append(listed, strings.Trim(value, "'"))
		}
		// The views that existed before the new ones keep their names, and
		// every newly registered view is selectable.
		want := []string{
			"auto", "dns", "graphql", "grpc", "hex dump", "hex stream", "http/3 frames", "image",
			"javascript", "json", "mqtt", "msgpack", "multipart form", "protobuf", "query", "raw",
			"socket.io", "url-encoded", "viewcss", "wbxml", "xml/html", "zip archive",
		}
		if diff := gocmp.Diff(want, listed); diff != "" {
			t.Fatalf("binary view choices (-want +got):\n%s", diff)
		}
		if diff := gocmp.Diff(contentviews.DefaultRegistry.AvailableViews(), listed); diff != "" {
			t.Fatalf("binary view choices differ from the registry (-registry +binary):\n%s", diff)
		}
	})
}
