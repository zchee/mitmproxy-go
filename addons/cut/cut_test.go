// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package cut

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T) (*Addon, *addon.Manager, *command.Manager) {
	t.Helper()
	opts := options.New()
	cmds := command.NewManager()
	m := addon.NewManager(opts, cmds, addon.Config{})
	a := New()
	if err := m.Add(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	return a, m, cmds
}

// TestExtract ports test_extract, test_extract_websocket, test_extract_str,
// test_headername and test_cut, including absent HTTP parts and non-HTTP flows.
func TestExtract(t *testing.T) {
	f := testflow.TFlow(testflow.WithResponse)
	f.Live = false
	tests := map[string]struct {
		spec string
		want any
	}{
		"method":                  {"request.method", "GET"},
		"scheme":                  {"request.scheme", "http"},
		"host":                    {"request.host", "address"},
		"http version":            {"request.http_version", "HTTP/1.1"},
		"port":                    {"request.port", "22"},
		"path":                    {"request.path", "/path"},
		"url":                     {"request.url", "http://address:22/path"},
		"text":                    {"request.text", "content"},
		"content":                 {"request.content", []byte("content")},
		"raw content":             {"request.raw_content", []byte("content")},
		"start":                   {"request.timestamp_start", "946681200"},
		"end":                     {"request.timestamp_end", "946681201"},
		"header":                  {"request.header[header]", "qvalue"},
		"header whitespace":       {"request.header[ header ]", "qvalue"},
		"missing header":          {"request.header[unknown]", ""},
		"status":                  {"response.status_code", "200"},
		"reason":                  {"response.reason", "OK"},
		"response text":           {"response.text", "message"},
		"response content":        {"response.content", []byte("message")},
		"response raw":            {"response.raw_content", []byte("message")},
		"response header":         {"response.header[header-response]", "svalue"},
		"response start":          {"response.timestamp_start", "946681202"},
		"response end":            {"response.timestamp_end", "946681203"},
		"client port":             {"client_conn.peername.port", "22"},
		"client host":             {"client_conn.peername.host", "127.0.0.1"},
		"client TLS":              {"client_conn.tls_version", "TLSv1.2"},
		"client sni":              {"client_conn.sni", "address"},
		"client established":      {"client_conn.tls_established", "true"},
		"server port":             {"server_conn.address.port", "22"},
		"server host":             {"server_conn.address.host", "address"},
		"server peer":             {"server_conn.peername.host", "192.168.0.1"},
		"server TLS":              {"server_conn.tls_version", "TLSv1.2"},
		"server sni":              {"server_conn.sni", "address"},
		"server established":      {"server_conn.tls_established", "true"},
		"unknown":                 {"moo", ""},
		"unknown nested":          {"moo.bar.baz", ""},
		"case sensitive":          {"request.METHOD", ""},
		"extra separators":        {"r_e_q_u_e_s_t.method", ""},
		"repeated header segment": {"request.header[x].header[x]", ""},
		"false bool":              {"live", "false"},
		"zero number":             {"response.nonexistent", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, cmds := setup(t)
			got, err := cmds.Call(t.Context(), "cut", []flow.Flow{f}, command.CutSpec{tt.spec})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(command.Data{{tt.want}}, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	data, err := os.ReadFile("../../testdata/mitmproxy-net/text_cert")
	if err != nil {
		t.Fatal(err)
	}
	f.ServerConn.CertificateList = [][]byte{data}
	got, err := extract("server_conn.certificate_list", f)
	if err != nil || !strings.Contains(got.(string), "CERTIFICATE") {
		t.Fatalf("certificate=%v err=%v", got, err)
	}
	for _, spec := range []string{"request.content", "response.content"} {
		got, err := extract(spec, testflow.TWebSocketFlow())
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"hello binary", "hello text", "it's me"} {
			if !bytes.Contains(got.([]byte), []byte(want)) {
				t.Fatalf("websocket=%q", got)
			}
		}
	}
	absent := testflow.TFlow()
	for _, spec := range []string{"response.reason", "response.header[key]"} {
		got, err := extract(spec, absent)
		if err != nil || got != "" {
			t.Fatalf("absent=%v err=%v", got, err)
		}
	}
	for _, f := range []flow.Flow{testflow.TTCPFlow(), testflow.TUDPFlow()} {
		got, err := extract("request.method", f)
		if err != nil || got != "" {
			t.Fatalf("non-http=%v err=%v", got, err)
		}
	}
	f.Request.RawContent = []byte{0xff}
	gotString, err := extractString("request.raw_content", f)
	if err != nil || gotString != `b'\xff'` {
		t.Fatalf("repr=%q err=%v", gotString, err)
	}
	errors := map[string]struct{ spec, want string }{
		"internal":        {"__dict__", "Can't access internal attribute __dict__"},
		"nested internal": {"missing._secret", "Can't access internal attribute _secret"},
		"missing bracket": {"request.header[foo", "Invalid header spec: header[foo"},
	}
	for name, tt := range errors {
		t.Run(name, func(t *testing.T) {
			_, err := extract(tt.spec, f)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("err=%v want=%q", err, tt.want)
			}
		})
	}
	if _, err := headername("header[foo."); err == nil || err.Error() != "Invalid header spec: header[foo." {
		t.Fatalf("header err=%v", err)
	}
}

// TestSave ports test_cut_save and all real-filesystem test_cut_save_open cases.
func TestSave(t *testing.T) {
	_, _, cmds := setup(t)
	f := testflow.TFlow(testflow.WithResponse)
	path := filepath.Join(t.TempDir(), "cuts")
	tests := map[string]struct {
		flows      []flow.Flow
		cuts       command.CutSpec
		append     bool
		seed, want []byte
	}{
		"method":         {[]flow.Flow{f}, command.CutSpec{"request.method"}, false, nil, []byte("GET")},
		"content":        {[]flow.Flow{f}, command.CutSpec{"request.content"}, false, nil, []byte("content")},
		"append content": {[]flow.Flow{f}, command.CutSpec{"request.content"}, true, []byte("content"), []byte("content\ncontent")},
		"append empty":   {[]flow.Flow{f}, command.CutSpec{"request.content"}, true, []byte{}, []byte("content")},
		"many flows":     {[]flow.Flow{f, f}, command.CutSpec{"request.method"}, false, nil, []byte("GET\r\nGET\r\n")},
		"many cuts":      {[]flow.Flow{f, f}, command.CutSpec{"request.method", "request.content"}, false, nil, []byte("GET,b'content'\r\nGET,b'content'\r\n")},
		"no cuts":        {[]flow.Flow{f}, nil, false, nil, []byte("\r\n")},
		"no flows":       {nil, command.CutSpec{"request.method"}, false, nil, []byte{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, tt.seed, 0o600); err != nil {
				t.Fatal(err)
			}
			p := path
			if tt.append {
				p = "+" + p
			}
			if _, err := cmds.Call(t.Context(), "cut.save", tt.flows, tt.cuts, command.Path(p)); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	badPaths := map[string]struct{ path, contains string }{
		"directory":      {t.TempDir(), "is a directory"},
		"missing parent": {filepath.Join(t.TempDir(), "missing", "cuts"), "no such file or directory"},
	}
	if runtime.GOOS != "windows" {
		denied := filepath.Join(t.TempDir(), "denied")
		if err := os.WriteFile(denied, nil, 0o400); err != nil {
			t.Fatal(err)
		}
		if os.Getuid() != 0 {
			badPaths["permission"] = struct{ path, contains string }{denied, "permission denied"}
		}
	}
	for name, tt := range badPaths {
		t.Run(name, func(t *testing.T) {
			logs.Reset()
			if _, err := cmds.Call(t.Context(), "cut.save", []flow.Flow{f}, command.CutSpec{"request.method"}, command.Path(tt.path)); err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && !strings.Contains(logs.String(), tt.contains) {
				t.Fatalf("log=%s", logs.String())
			}
		})
	}
}

func TestAttributeName(t *testing.T) {
	tests := map[string]struct{ field, want string }{
		"HTTP version":      {"HTTPVersion", "http_version"},
		"TLS time":          {"TimestampTLSSetup", "timestamp_tls_setup"},
		"client connection": {"ClientConn", "client_conn"},
		"SNI":               {"SNI", "sni"},
		"ALPN":              {"ALPNOffers", "alpn_offers"},
		"body":              {"RawContent", "raw_content"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, attributeName(tt.field)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestCSV(t *testing.T) {
	tests := map[string]struct {
		row  []string
		want string
	}{
		"empty row":       {nil, "\r\n"},
		"single empty":    {[]string{""}, "\"\"\r\n"},
		"multiple empty":  {[]string{"", ""}, ",\r\n"},
		"leading space":   {[]string{" a"}, " a\r\n"},
		"comma":           {[]string{"a,b"}, "\"a,b\"\r\n"},
		"quotes":          {[]string{"a\"b"}, "\"a\"\"b\"\r\n"},
		"carriage return": {[]string{"a\rb"}, "\"a\rb\"\r\n"},
		"newline":         {[]string{"a\nb"}, "\"a\nb\"\r\n"},
		"unicode":         {[]string{"é"}, "é\r\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			writeCSVRow(&out, tt.row)
			if diff := cmp.Diff(tt.want, out.String()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestTables(t *testing.T) {
	_, _, cmds := setup(t)
	tests := map[string]struct{ signature string }{
		"cut":      {"cut flows cuts -> data[][]"},
		"cut.save": {"cut.save flows cuts path"},
		"cut.clip": {"cut.clip flows cuts"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for n, c := range cmds.Commands() {
				if n == name {
					if diff := cmp.Diff(tt.signature, c.SignatureHelp()); diff != "" {
						t.Fatal(diff)
					}
					return
				}
			}
			t.Fatal("missing command")
		})
	}
	// Upstream Cut has no options.
}
