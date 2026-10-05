// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

// TestExpectedBodySize ports every branch of test_expected_http_body_size.
func TestExpectedBodySize(t *testing.T) {
	tests := map[string]struct {
		method  string
		status  int
		headers httpmsg.Headers
		want    BodySize
		invalid string
	}{
		"expect continue":               {headers: fields("expect", "100-continue", "content-length", "42"), want: BodySize{BodyLength, 42}},
		"HEAD":                          {method: "HEAD", status: 200, headers: fields("content-length", "42"), want: BodySize{Mode: BodyNone}},
		"CONNECT request":               {method: "CONNECT", want: BodySize{Mode: BodyNone}},
		"CONNECT response":              {method: "CONNECT", status: 200, want: BodySize{Mode: BodyNone}},
		"informational":                 {status: 100, want: BodySize{Mode: BodyNone}},
		"no content":                    {status: 204, want: BodySize{Mode: BodyNone}},
		"not modified":                  {status: 304, want: BodySize{Mode: BodyNone}},
		"chunked":                       {headers: fields("transfer-encoding", "chunked"), want: BodySize{Mode: BodyChunked}},
		"gzip chunked":                  {headers: fields("transfer-encoding", "gzip,\tchunked"), want: BodySize{Mode: BodyChunked}},
		"invalid unicode":               {headers: fields("transfer-encoding", "chunKed"), invalid: "invalid transfer-encoding header"},
		"space in encoding":             {headers: fields("transfer-encoding", "chun ked"), invalid: "unknown transfer-encoding header"},
		"unknown encoding":              {headers: fields("transfer-encoding", "qux"), invalid: "unknown transfer-encoding header"},
		"response gzip":                 {status: 200, headers: fields("transfer-encoding", "gzip"), want: BodySize{Mode: BodyUntilClose}},
		"identity with length":          {headers: fields("transfer-encoding", "identity", "content-length", "42"), want: BodySize{BodyLength, 42}},
		"identity alone":                {headers: fields("transfer-encoding", "identity"), want: BodySize{Mode: BodyNone}},
		"request gzip":                  {headers: fields("transfer-encoding", "gzip"), want: BodySize{Mode: BodyUntilClose}},
		"length":                        {headers: fields("content-length", "42"), want: BodySize{BodyLength, 42}},
		"zero length":                   {headers: fields("content-length", "0"), want: BodySize{BodyLength, 0}},
		"invalid length":                {headers: fields("content-length", "foo"), invalid: "invalid content-length header"},
		"equal lengths":                 {headers: fields("content-length", "42", "content-length", "42"), invalid: "invalid content-length header"},
		"different lengths":             {headers: fields("content-length", "42", "content-length", "43"), invalid: "invalid content-length header"},
		"empty request":                 {want: BodySize{Mode: BodyNone}},
		"empty response":                {status: 200, want: BodySize{Mode: BodyUntilClose}},
		"chunked wins length":           {headers: fields("transfer-encoding", "chunked", "content-length", "invalid"), want: BodySize{Mode: BodyChunked}},
		"no body wins invalid":          {status: 204, headers: fields("transfer-encoding", "invalid", "content-length", "invalid"), want: BodySize{Mode: BodyNone}},
		"response encoding wins length": {status: 200, headers: fields("transfer-encoding", "gzip", "content-length", "42"), want: BodySize{Mode: BodyUntilClose}},
		"request gzip with length":      {headers: fields("transfer-encoding", "gzip", "content-length", "42"), want: BodySize{BodyLength, 42}},
		"empty framing":                 {headers: fields("transfer-encoding", "", "content-length", ""), want: BodySize{Mode: BodyNone}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req := &httpmsg.Request{Method: tt.method, Headers: tt.headers}
			var resp *httpmsg.Response
			if tt.status != 0 {
				resp = &httpmsg.Response{StatusCode: tt.status, Headers: tt.headers}
				req.Headers = nil
			}
			got, err := ExpectedBodySize(req, resp)
			if tt.invalid != "" {
				if err == nil || !strings.Contains(err.Error(), tt.invalid) {
					t.Fatalf("error=%v, want %q", err, tt.invalid)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestConnectionClose also covers test_get_header_tokens without exporting it.
func TestConnectionClose(t *testing.T) {
	tests := map[string]struct {
		version string
		headers httpmsg.Headers
		want    bool
	}{
		"HTTP 1.0":              {version: "HTTP/1.0", want: true},
		"HTTP 1.1":              {version: "HTTP/1.1"},
		"HTTP 2.0":              {version: "HTTP/2.0"},
		"keep alive":            {version: "HTTP/1.0", headers: fields("Connection", "keep-alive")},
		"close":                 {version: "HTTP/1.1", headers: fields("Connection", "close"), want: true},
		"unknown old":           {version: "HTTP/1.0", headers: fields("Connection", "foobar"), want: true},
		"unknown new":           {version: "HTTP/1.1", headers: fields("Connection", "foobar")},
		"case sensitive":        {version: "HTTP/1.1", headers: fields("Connection", "CLOSE")},
		"split repeated tokens": {version: "HTTP/1.1", headers: fields("Connection", "bar, keep-alive", "connection", " close "), want: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ConnectionClose(tt.version, tt.headers); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func fields(pairs ...string) httpmsg.Headers {
	h := make(httpmsg.Headers, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		h.Add(pairs[i], pairs[i+1])
	}
	return h
}
