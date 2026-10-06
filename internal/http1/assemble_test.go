// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"strings"
	"sync"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// These cover test_assemble_{request,response}_head/line/headers. Whole-message
// assembly and missing-content checks are tested with the streaming body API.
func TestAssembleHeads(t *testing.T) {
	tests := map[string]struct{ method, authority, scheme, want string }{
		"origin":    {method: "GET", want: "GET /path HTTP/1.1"},
		"authority": {method: "CONNECT", authority: "address:22", want: "CONNECT address:22 HTTP/1.1"},
		"absolute":  {method: "GET", authority: "address:22", scheme: "http", want: "GET http://address:22/path HTTP/1.1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := testflow.TReq()
			r.Method = tt.method
			r.Authority = tt.authority
			r.Scheme = tt.scheme
			got := AssembleRequestHead(r, nil, false, nil)
			want := tt.want + "\r\nheader: qvalue\r\ncontent-length: 7\r\n\r\n"
			if string(got) != want {
				t.Fatalf("got %q want %q", got, want)
			}
			r.Headers.Add("Transfer-Encoding", "chunked")
			if !strings.Contains(string(AssembleRequestHead(r, nil, false, nil)), "Transfer-Encoding: chunked\r\n") {
				t.Fatal("lost transfer encoding")
			}
		})
	}
	r := testflow.TResp()
	if got := string(AssembleResponseHead(r, nil, false, nil)); got != "HTTP/1.1 200 OK\r\nheader-response: svalue\r\ncontent-length: 7\r\n\r\n" {
		t.Fatalf("response=%q", got)
	}
	r.Headers.Add("Transfer-Encoding", "chunked")
	if !strings.Contains(string(AssembleResponseHead(r, nil, false, nil)), "Transfer-Encoding: chunked\r\n") {
		t.Fatal("lost transfer encoding")
	}
}

func TestHeadFidelity(t *testing.T) {
	tests := map[string]struct {
		raw, want  string
		addon      bool
		changePath string
		length     string
		count      uint64
	}{
		"mixed normalized folds": {raw: "GET / HTTP/1.1\r\nX: one\r\n two\r\n\tthree\r\n\r\n", want: "GET / HTTP/1.1\r\nX: one\r\n two\r\n three\r\n\r\n", count: 1},
		"fold header spacing":    {raw: "GET / HTTP/1.1\r\nX:one\r\n two\r\n\r\n", want: "GET / HTTP/1.1\r\nX: one\r\n two\r\n\r\n", count: 1},
		"unchanged raw fields":   {raw: "GET  / HTTP/1.1\nX-Foo:one\nx-bar:\ttwo \nX-FOO: three\n\n", want: "GET  / HTTP/1.1\nX-Foo:one\nx-bar:\ttwo \nX-FOO: three\n\n"},
		"fold normalized":        {raw: "GET / HTTP/1.1\r\nX: one\r\n\ttwo\r\n\r\n", want: "GET / HTTP/1.1\r\nX: one\r\n two\r\n\r\n", count: 1},
		"addon excluded":         {raw: "GET / HTTP/1.1\r\nX: one\r\n\ttwo\r\n\r\n", want: "GET /edited HTTP/1.1\r\nX: one\r\n two\r\n\r\n", addon: true, changePath: "/edited"},
		"proxy target rewrite":   {raw: "GET / HTTP/1.1\r\nX:y\r\n\r\n", want: "GET /edited HTTP/1.1\r\nX:y\r\n\r\n", changePath: "/edited", count: 1},
		"framing rewrite":        {raw: "GET / HTTP/1.1\r\nContent-Length: 1\r\nX:y\r\n\r\n", want: "GET / HTTP/1.1\r\nContent-Length: 2\r\nX:y\r\n\r\n", length: "2", count: 1},
		// The proxy frames a message by the trimmed value, so a value whose
		// wire bytes carry other trimmed whitespace leaves in the trimmed form.
		"transfer encoding form feed":    {raw: "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\f\r\nX:y\r\n\r\n", want: "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX:y\r\n\r\n", count: 1},
		"content length vertical tab":    {raw: "POST / HTTP/1.1\r\nContent-Length:\v5\v\r\nX:y\r\n\r\n", want: "POST / HTTP/1.1\r\nContent-Length: 5\r\nX:y\r\n\r\n", count: 1},
		"content length bare CR":         {raw: "POST / HTTP/1.1\r\nContent-Length: 5\r\r\nX:y\r\n\r\n", want: "POST / HTTP/1.1\r\nContent-Length: 5\r\nX:y\r\n\r\n", count: 1},
		"content length bare CR LF only": {raw: "POST / HTTP/1.1\nContent-Length: 5\r\r\nX:y\n\n", want: "POST / HTTP/1.1\nContent-Length: 5\r\nX:y\n\n", count: 1},
		"other header control bytes":     {raw: "GET / HTTP/1.1\r\nX: \fone\v\r\nY: two \t\r\n\r\n", want: "GET / HTTP/1.1\r\nX: one\r\nY: two \t\r\n\r\n", count: 1},
		"both framing families":          {raw: "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\f\r\nContent-Length: 5\v\r\n\r\n", want: "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", count: 2},
		"request line vertical tab":      {raw: "GET\v/ HTTP/1.1\r\nX:y\r\n\r\n", want: "GET / HTTP/1.1\r\nX:y\r\n\r\n", count: 1},
		"request line form feed":         {raw: "GET /\fHTTP/1.1\r\nX:y\r\n\r\n", want: "GET / HTTP/1.1\r\nX:y\r\n\r\n", count: 1},
		"request line bare CR":           {raw: "GET / HTTP/1.1\r\r\nX:y\r\n\r\n", want: "GET / HTTP/1.1\r\nX:y\r\n\r\n", count: 1},
		"request line leading spaces":    {raw: "  POST / HTTP/1.1\r\nX:y\r\n\r\n", want: "POST / HTTP/1.1\r\nX:y\r\n\r\n", count: 1},
		"request line leading tab":       {raw: "\tPOST / HTTP/1.1\r\nX:y\r\n\r\n", want: "POST / HTTP/1.1\r\nX:y\r\n\r\n", count: 1},
		"request line leading blanks LF": {raw: "\n \tPOST / HTTP/1.1\nX:y\n\n", want: "POST / HTTP/1.1\r\nX:y\n\n", count: 1},
		"request line addon attribution": {raw: "  POST / HTTP/1.1\r\nX:y\r\n\r\n", want: "POST / HTTP/1.1\r\nX:y\r\n\r\n", addon: true},
		"request line tab kept":          {raw: "GET\t/ HTTP/1.1\r\nX:y\r\n\r\n", want: "GET\t/ HTTP/1.1\r\nX:y\r\n\r\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			head, err := ReadRequestHead(bufio.NewReader(strings.NewReader(tt.raw)))
			if err != nil {
				t.Fatal(err)
			}
			if tt.changePath != "" {
				head.Request.Path = tt.changePath
			}
			if tt.length != "" {
				head.Request.Headers.Set("Content-Length", tt.length)
			}
			var counter FidelityCounter
			if got := string(AssembleRequestHead(head.Request, &head, tt.addon, &counter)); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
			if got := counter.Load(); got != tt.count {
				t.Fatalf("normalizations=%d want %d", got, tt.count)
			}
		})
	}
}

func TestResponseHeadFidelity(t *testing.T) {
	tests := map[string]struct {
		raw, want string
		count     uint64
	}{
		"unchanged spacing":         {raw: "HTTP/1.1  200\tNot  Found\r\nX:y\r\n\r\n", want: "HTTP/1.1  200\tNot  Found\r\nX:y\r\n\r\n"},
		"leading whitespace":        {raw: " \tHTTP/1.1 200 OK\r\nX:y\r\n\r\n", want: "HTTP/1.1 200 OK\r\nX:y\r\n\r\n", count: 1},
		"empty reason":              {raw: "HTTP/1.1 204\r\n\r\n", want: "HTTP/1.1 204\r\n\r\n"},
		"Python integer status":     {raw: "HTTP/1.1 +0_204 No Content\r\n\r\n", want: "HTTP/1.1 204 No Content\r\n\r\n", count: 1},
		"vertical tab separator":    {raw: "HTTP/1.1\v200 OK\r\n\r\n", want: "HTTP/1.1 200 OK\r\n\r\n", count: 1},
		"control byte in reason":    {raw: "HTTP/1.1 200 O\vK\r\n\r\n", want: "HTTP/1.1 200 O\vK\r\n\r\n"},
		"content length form feed":  {raw: "HTTP/1.1 200 OK\r\nContent-Length: 2\f\r\n\r\n", want: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", count: 1},
		"transfer encoding bare CR": {raw: "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\r\r\n\n", want: "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\r\n\n", count: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			head, err := ReadResponseHead(bufio.NewReader(strings.NewReader(tt.raw)))
			if err != nil {
				t.Fatal(err)
			}
			var counter FidelityCounter
			if got := string(AssembleResponseHead(head.Response, &head, false, &counter)); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
			if got := counter.Load(); got != tt.count {
				t.Fatalf("normalizations=%d want %d", got, tt.count)
			}
		})
	}
}

func TestIndependentReadersAndCounter(t *testing.T) {
	var counter FidelityCounter
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 20 {
				head, err := ReadResponseHead(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nX: a\r\n\tb\r\n\r\n")))
				if err != nil {
					t.Error(err)
					return
				}
				AssembleResponseHead(head.Response, &head, false, &counter)
			}
		})
	}
	wg.Wait()
	if got := counter.Load(); got != 640 {
		t.Fatalf("normalizations=%d want 640", got)
	}
}
