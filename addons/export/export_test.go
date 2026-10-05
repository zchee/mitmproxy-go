// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package export

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T) (*Addon, *addon.Manager, *command.Manager) {
	t.Helper()
	opts := options.New()
	cmds := command.NewManager()
	manager := addon.NewManager(opts, cmds, addon.Config{})
	a := New(opts)
	if err := manager.Add(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	return a, manager, cmds
}

// These cases port every TestExportCurlCommand and TestExportHttpieCommand
// test function from the pinned upstream test_export.py.
func TestConsoleFormats(t *testing.T) {
	get := func() *flow.HTTPFlow {
		f := testflow.TFlow()
		f.Request.RawContent = []byte{}
		f.Request.Path = "/path?a=foo&a=bar&b=baz"
		f.Request.Headers.Set("content-length", "0")
		return f
	}
	post := func(body []byte) *flow.HTTPFlow {
		f := testflow.TFlow()
		f.Request.Method = "POST"
		f.Request.Headers = nil
		f.Request.RawContent = body
		return f
	}
	patch := func() *flow.HTTPFlow {
		f := testflow.TFlow()
		f.Request.Method = "PATCH"
		f.Request.Path = "/path?query=param"
		return f
	}
	binary := func() *flow.HTTPFlow {
		body := make([]byte, 256)
		for i := range body {
			body[i] = byte(i)
		}
		f := post(body)
		f.Request.Headers.Set("Content-Type", "application/json; charset=utf-8")
		return f
	}
	domain := func() *flow.HTTPFlow { f := get(); f.Request.Headers.Set("host", "domain:22"); return f }
	stripped := get()
	stripped.Request.Headers = nil
	stripped.Request.Headers.Set("host", "address")
	stripped.Request.Headers.Set(":authority", "address")
	stripped.Request.Headers.Set("accept-encoding", "br")
	tests := map[string]struct {
		format   string
		f        flow.Flow
		preserve bool
		want     string
		err      string
	}{
		"curl/test_get":  {format: "curl", f: get(), want: "curl -H 'header: qvalue' 'http://address:22/path?a=foo&a=bar&b=baz'"},
		"curl/test_post": {format: "curl", f: post([]byte("nobinarysupport")), want: "curl -X POST http://address:22/path -d nobinarysupport"},
		"curl/test_post_with_no_content_has_explicit_content_length_header": {format: "curl", f: post(nil), want: "curl -H 'content-length: 0' -X POST http://address:22/path"},
		"curl/test_fails_with_binary_data":                                  {format: "curl", f: binary(), err: "Request content must be valid unicode"},
		"curl/test_patch":                                                   {format: "curl", f: patch(), want: "curl -H 'header: qvalue' -X PATCH 'http://address:22/path?query=param' -d content"},
		"curl/test_tcp":                                                     {format: "curl", f: testflow.TTCPFlow(), err: "Can't export flow with no request."},
		"curl/test_udp":                                                     {format: "curl", f: testflow.TUDPFlow(), err: "Can't export flow with no request."},
		"curl/test_escape_single_quotes_in_body":                            {format: "curl", f: post([]byte("'&#")), want: `curl -X POST http://address:22/path -d ''"'"'&#'`},
		"curl/test_expand_escaped":                                          {format: "curl", f: post([]byte("foo\nbar")), want: `curl -X POST http://address:22/path -d "$(printf 'foo\x0abar')"`},
		"curl/test_no_expand_when_no_escaped":                               {format: "curl", f: post([]byte("foobar")), want: "curl -X POST http://address:22/path -d foobar"},
		"curl/test_strip_unnecessary":                                       {format: "curl", f: stripped, want: "curl --compressed 'http://address:22/path?a=foo&a=bar&b=baz'"},
		"curl/test_correct_host_used":                                       {format: "curl", f: domain(), want: "curl -H 'header: qvalue' -H 'host: domain:22' 'http://domain:22/path?a=foo&a=bar&b=baz'"},
		"curl/test_correct_host_used/preserve":                              {format: "curl", f: domain(), preserve: true, want: "curl --resolve 'domain:22:[192.168.0.1]' -H 'header: qvalue' -H 'host: domain:22' 'http://domain:22/path?a=foo&a=bar&b=baz'"},
		"httpie/test_get":                                                   {format: "httpie", f: get(), want: "http GET 'http://address:22/path?a=foo&a=bar&b=baz' 'header: qvalue'"},
		"httpie/test_post":                                                  {format: "httpie", f: post([]byte("nobinarysupport")), want: "http POST http://address:22/path <<< nobinarysupport"},
		"httpie/test_fails_with_binary_data":                                {format: "httpie", f: binary(), err: "Request content must be valid unicode"},
		"httpie/test_patch":                                                 {format: "httpie", f: patch(), want: "http PATCH 'http://address:22/path?query=param' 'header: qvalue' <<< content"},
		"httpie/test_tcp":                                                   {format: "httpie", f: testflow.TTCPFlow(), err: "Can't export flow with no request."},
		"httpie/test_udp":                                                   {format: "httpie", f: testflow.TUDPFlow(), err: "Can't export flow with no request."},
		"httpie/test_escape_single_quotes_in_body":                          {format: "httpie", f: post([]byte("'&#")), want: `http POST http://address:22/path <<< ''"'"'&#'`},
		"httpie/test_correct_host_used":                                     {format: "httpie", f: domain(), want: "http GET 'http://domain:22/path?a=foo&a=bar&b=baz' 'header: qvalue' 'host: domain:22'"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, m, _ := setup(t)
			before := tt.f.GetState()
			var got []byte
			var err error
			if e := m.Do(t.Context(), func(ctx context.Context) error {
				if tt.preserve {
					if e := a.options.Set(ctx, "export_preserve_original_ip=true"); e != nil {
						return e
					}
				}
				got, err = a.format(tt.format, tt.f)
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if tt.err != "" {
				if err == nil || err.Error() != tt.err {
					t.Fatalf("error = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, string(got)); diff != "" {
				t.Fatal(diff)
			}
			if diff := cmp.Diff(before, tt.f.GetState()); diff != "" {
				t.Fatalf("export mutated flow: %s", diff)
			}
		})
	}
}

// TestRawFormats ports TestRaw, TestRawRequest and TestRawResponse in full.
func TestRawFormats(t *testing.T) {
	missingReq := testflow.TFlow()
	missingReq.Request.RawContent = nil
	missingResp := testflow.TFlow(testflow.WithResponse)
	missingResp.Response.RawContent = nil
	responseOnly := testflow.TFlow(testflow.WithResponse)
	responseOnly.Request.RawContent = nil
	head := testflow.TFlow(testflow.WithResponse)
	head.Request.Method = "HEAD"
	head.Response.RawContent = []byte{}
	head.Response.Headers = httpmsg.Headers{}
	head.Response.Headers.Set("content-length", "7")
	tests := map[string]struct {
		format   string
		f        flow.Flow
		contains []string
		err      string
	}{
		"raw/test_req_and_resp_present":              {"raw", testflow.TFlow(testflow.WithResponse), []string{"header: qvalue", "header-response: svalue"}, ""},
		"raw/test_get_request_present":               {"raw", testflow.TFlow(), []string{"header: qvalue"}, ""},
		"raw/test_get_response_present":              {"raw", responseOnly, []string{"header-response: svalue"}, ""},
		"raw/test_tcp":                               {"raw", testflow.TTCPFlow(), nil, "Can't export flow with no request or response."},
		"raw/test_udp":                               {"raw", testflow.TUDPFlow(), nil, "Can't export flow with no request or response."},
		"raw/test_websocket":                         {"raw", testflow.TWebSocketFlow(), []string{"hello binary", "hello text", "it's me"}, ""},
		"request/test_get":                           {"raw_request", testflow.TFlow(), []string{"header: qvalue"}, ""},
		"request/test_no_content":                    {"raw_request", missingReq, nil, "Request content missing."},
		"request/test_tcp":                           {"raw_request", testflow.TTCPFlow(), nil, "Can't export flow with no request."},
		"request/test_udp":                           {"raw_request", testflow.TUDPFlow(), nil, "Can't export flow with no request."},
		"response/test_get":                          {"raw_response", testflow.TFlow(testflow.WithResponse), []string{"header-response: svalue"}, ""},
		"response/test_no_content":                   {"raw_response", missingResp, nil, "Response content missing."},
		"response/test_tcp":                          {"raw_response", testflow.TTCPFlow(), nil, "Can't export flow with no response."},
		"response/test_udp":                          {"raw_response", testflow.TUDPFlow(), nil, "Can't export flow with no response."},
		"response/test_head_non_zero_content_length": {"raw_response", head, []string{"content-length: 7\r\n"}, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, _, _ := setup(t)
			got, err := a.format(tt.format, tt.f)
			if tt.err != "" {
				if err == nil || err.Error() != tt.err {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tt.contains {
				if !strings.Contains(string(got), s) {
					t.Fatalf("%q lacks %q", got, s)
				}
			}
		})
	}
}

// TestExport ports test_export, test_export_open, test_export_str, test_clip.
// Clipboard transport calls are verified in the build-tag-specific tests;
// filesystem errors use real paths rather than patching Python's open().
func TestExport(t *testing.T) {
	a, _, cmds := setup(t)
	formats := []string{"curl", "httpie", "raw", "raw_request", "raw_response"}
	got, err := cmds.Call(t.Context(), "export.formats")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(formats, got); diff != "" {
		t.Fatal(diff)
	}
	tests := map[string]struct{ format string }{"curl": {"curl"}, "httpie": {"httpie"}, "raw": {"raw"}, "request": {"raw_request"}, "response": {"raw_response"}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "export")
			f := testflow.TFlow(testflow.WithResponse)
			if _, err := cmds.Call(t.Context(), "export.file", tt.format, flow.Flow(f), command.Path(path)); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil || len(data) == 0 {
				t.Fatalf("data=%q err=%v", data, err)
			}
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm()&0o077 != 0 {
				t.Fatalf("mode=%v", st.Mode())
			}
		})
	}
	if _, err := a.format("nonexistent", testflow.TFlow()); err == nil || err.Error() != "No such export format: nonexistent" {
		t.Fatalf("error=%v", err)
	}
	if _, err := cmds.Call(t.Context(), "export.clip", "nonexistent", flow.Flow(testflow.TFlow())); err == nil {
		t.Fatal("missing format accepted")
	}
	f := testflow.TFlow()
	f.Request.Headers = httpmsg.Headers{{Name: []byte("utf8-header"), Value: []byte("é")}, {Name: []byte("latin1-header"), Value: []byte{0xe9}}}
	for _, format := range []string{"curl", "raw"} {
		v, err := cmds.Call(t.Context(), "export", format, flow.Flow(f))
		if err != nil {
			t.Fatal(err)
		}
		if !utf8.Valid(v.([]byte)) {
			t.Fatalf("invalid UTF-8: %q", v)
		}
	}
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing", "export")} {
		if _, err := cmds.Call(t.Context(), "export.file", "raw_request", flow.Flow(testflow.TFlow()), command.Path(path)); err != nil {
			t.Fatalf("OS failure must be logged, not returned: %v", err)
		}
	}
}

func TestTables(t *testing.T) {
	a, _, cmds := setup(t)
	opt, ok := a.options.Lookup("export_preserve_original_ip")
	if !ok {
		t.Fatal("missing option")
	}
	if opt.Type() != options.TypeBool {
		t.Fatal("wrong type")
	}
	if diff := cmp.Diff(false, opt.Default()); diff != "" {
		t.Fatal(diff)
	}
	tests := map[string]struct {
		signature string
		types     []string
	}{"export.formats": {"export.formats  -> str[]", nil}, "export.file": {"export.file format flow path", []string{"Str", "Flow", "Path"}}, "export.clip": {"export.clip format f", []string{"Str", "Flow"}}, "export": {"export format f -> bytes", []string{"Str", "Flow"}}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var c *command.Command
			for n, cmd := range cmds.Commands() {
				if n == name {
					c = cmd
					break
				}
			}
			if c == nil {
				t.Fatal("missing command")
			}
			if diff := cmp.Diff(tt.signature, c.SignatureHelp()); diff != "" {
				t.Fatal(diff)
			}
			var types []string
			for _, p := range c.Params {
				types = append(types, p.Type.Name())
			}
			if diff := cmp.Diff(tt.types, types); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
