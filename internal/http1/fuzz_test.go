// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"bytes"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func FuzzRead(f *testing.F) {
	for _, seed := range []string{"GET / HTTP/1.1\r\nX-Foo: a\r\nx-bar: b\r\n\r\n", "CONNECT host:443 HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "GET http://foo:42/bar HTTP/1.1\r\nSet-Cookie: a=b;\r\n\tSecure\r\n\r\n", "GET / WTF/1.1\r\n\r\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxHeadBytes+1 {
			return
		}
		if head, err := ReadRequestHead(bufio.NewReader(bytes.NewReader(raw))); err == nil {
			if head.Consumed > len(raw) || !bytes.Equal(head.Raw, raw[:head.Consumed]) {
				t.Fatal("invalid consumption")
			}
		}
		if head, err := ReadResponseHead(bufio.NewReader(bytes.NewReader(raw))); err == nil {
			if head.Consumed > len(raw) || !bytes.Equal(head.Raw, raw[:head.Consumed]) {
				t.Fatal("invalid response consumption")
			}
		}
	})
}

func FuzzAssemble(f *testing.F) {
	for _, seed := range []string{"GET / HTTP/1.1\r\n\r\n", "GET / HTTP/1.1\r\nX: a\r\n\tb\r\n\r\n", "HTTP/1.0 204\r\nContent-Length: 42\r\n\r\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxHeadBytes {
			return
		}
		if head, err := ReadRequestHead(bufio.NewReader(bytes.NewReader(raw))); err == nil {
			assembled := AssembleRequestHead(head.Request, &head, false, nil)
			again, err := ReadRequestHead(bufio.NewReader(bytes.NewReader(assembled)))
			if err != nil {
				t.Fatalf("reparse %q: %v", assembled, err)
			}
			head.Request.TimestampStart, again.Request.TimestampStart = 0, 0
			if diff := gocmp.Diff(head.Request, again.Request); diff != "" {
				t.Fatalf("request round trip: %s", diff)
			}
		}
		if head, err := ReadResponseHead(bufio.NewReader(bytes.NewReader(raw))); err == nil {
			assembled := AssembleResponseHead(head.Response, &head, false, nil)
			again, err := ReadResponseHead(bufio.NewReader(bytes.NewReader(assembled)))
			if err != nil {
				t.Fatalf("reparse %q: %v", assembled, err)
			}
			head.Response.TimestampStart, again.Response.TimestampStart = 0, 0
			if diff := gocmp.Diff(head.Response, again.Response); diff != "" {
				t.Fatalf("response round trip: %s", diff)
			}
		}
	})
}
