// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package export

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestShellQuote(t *testing.T) {
	tests := map[string]struct{ input, want string }{"empty": {"", "''"}, "safe": {"abc_@%+=:,./-", "abc_@%+=:,./-"}, "space": {"a b", "'a b'"}, "quote": {"a'b", `'a'"'"'b'`}, "unicode": {"é", "'é'"}, "substitution": {"$(echo a)", "'$(echo a)'"}, "newline": {"a\nb", "'a\nb'"}, "invalid byte": {"\xff", "'\xff'"}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, shellQuote(tt.input)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestMethodCasing(t *testing.T) {
	a, _, _ := setup(t)
	f := testflow.TFlow()
	f.Request.Method = "get"
	f.Request.Headers = nil
	f.Request.RawContent = []byte{}
	tests := map[string]struct{ format, want string }{
		"curl":   {"curl", "curl http://address:22/path"},
		"httpie": {"httpie", "http GET http://address:22/path"},
		"raw":    {"raw_request", "get /path HTTP/1.1\r\n\r\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := a.format(tt.format, f)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, string(got)); diff != "" {
				t.Fatal(diff)
			}
			if f.Request.Method != "get" {
				t.Fatal("export mutated captured method")
			}
		})
	}
}

func TestRawAssembly(t *testing.T) {
	a, _, _ := setup(t)
	tests := map[string]struct {
		headers  httpmsg.Headers
		body     []byte
		trailers httpmsg.Headers
		want     string
		bad      bool
	}{
		"chunked":           {httpmsg.Headers{{Name: []byte("transfer-encoding"), Value: []byte("chunked")}}, []byte("abc"), nil, "GET /path HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", false},
		"empty chunked":     {httpmsg.Headers{{Name: []byte("transfer-encoding"), Value: []byte("chunked")}}, []byte{}, nil, "GET /path HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", false},
		"unframed trailers": {nil, []byte{}, httpmsg.Headers{{Name: []byte("x"), Value: []byte("y")}}, "", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TFlow()
			f.Request.Headers = tt.headers
			f.Request.RawContent = tt.body
			f.Request.Trailers = tt.trailers
			got, err := a.format("raw_request", f)
			if tt.bad {
				if err == nil {
					t.Fatal("accepted invalid trailers")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, string(got)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	f := testflow.TFlow(testflow.WithResponse)
	req, _ := a.format("raw_request", f)
	resp, _ := a.format("raw_response", f)
	got, err := a.format("raw", f)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Join([][]byte{req, resp}, []byte("\r\n\r\n"))
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
	original := testflow.TFlow()
	original.Request.RawContent = []byte("body")
	if err := original.Request.Encode("gzip"); err != nil {
		t.Fatal(err)
	}
	data, err := a.format("raw_request", original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("body")) || bytes.Contains(data, []byte("content-encoding")) {
		t.Fatalf("not decoded: %q", data)
	}
	var absent *flow.HTTPFlow
	if _, err := a.format("raw", absent); err == nil {
		t.Fatal("accepted nil flow")
	}
}
