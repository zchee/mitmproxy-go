// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

// The tables port test_read.py's request/response lines, heads and TestReadHeaders.
func TestReadRequestHead(t *testing.T) {
	tests := map[string]struct {
		line                            string
		host                            string
		port                            int
		method, scheme, authority, path string
		invalid                         bool
	}{
		"IDNA absolute authority": {line: "GET http://xn--aaa-pla.example:80/ HTTP/1.1", host: "äaaa.example", port: 80, method: "GET", scheme: "http", authority: "xn--aaa-pla.example:80", path: "/"},
		"IDNA CONNECT authority":  {line: "CONNECT xn--r8jz45g.xn--zckzah:443 HTTP/1.1", host: "例え.テスト", port: 443, method: "CONNECT", authority: "xn--r8jz45g.xn--zckzah:443"},
		"invalid IDNA authority":  {line: "CONNECT xn--abc:443 HTTP/1.1", invalid: true},
		"origin":                  {line: "GET / HTTP/1.1", method: "GET", path: "/"},
		"asterisk":                {line: "OPTIONS * HTTP/1.1", method: "OPTIONS", path: "*"},
		"authority":               {line: "CONNECT foo:42 HTTP/1.1", host: "foo", port: 42, method: "CONNECT", authority: "foo:42"},
		"absolute":                {line: "GET http://foo:42/bar HTTP/1.1", host: "foo", port: 42, method: "GET", scheme: "http", authority: "foo:42", path: "/bar"},
		"absolute without path":   {line: "GET http://foo:42 HTTP/1.1", host: "foo", port: 42, method: "GET", scheme: "http", authority: "foo:42", path: "/"},
		"uppercase scheme":        {line: "GET HTTP://foo:42/bar HTTP/1.1", host: "foo", port: 42, method: "GET", scheme: "http", authority: "foo:42", path: "/bar"},
		"default port":            {line: "GET https://foo/ HTTP/1.1", host: "foo", port: 443, method: "GET", scheme: "https", authority: "foo", path: "/"},
		"ASCII whitespace":        {line: "\tGET\v/\fHTTP/1.1 ", method: "GET", path: "/"},
		"invalid version":         {line: "GET / WTF/1.1", invalid: true},
		"missing port":            {line: "CONNECT example.com HTTP/1.1", invalid: true},
		"unknown default port":    {line: "GET ws://example.com/ HTTP/1.1", invalid: true},
		"wrong token count":       {line: "this is not http", invalid: true},
		"empty":                   {line: "", invalid: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			wire := tt.line + "\r\nContent-Length: 4\r\n\r\n"
			reader := bufio.NewReader(iotest.OneByteReader(strings.NewReader(wire + "bodyNEXT")))
			head, err := ReadRequestHead(reader)
			if tt.invalid {
				if err == nil {
					t.Fatal("malformed request accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := &httpmsg.Request{Host: tt.host, Port: tt.port, Method: tt.method, Scheme: tt.scheme, Authority: tt.authority, Path: tt.path, HTTPVersion: "HTTP/1.1", Headers: httpmsg.Headers{{Name: []byte("Content-Length"), Value: []byte("4")}}}
			head.Request.TimestampStart = 0
			if diff := gocmp.Diff(want, head.Request); diff != "" {
				t.Fatalf("request (-want +got):\n%s", diff)
			}
			if string(head.Raw) != wire || head.Consumed != len(wire) {
				t.Fatalf("raw=%q consumed=%d", head.Raw, head.Consumed)
			}
			left, err := io.ReadAll(reader)
			if err != nil || string(left) != "bodyNEXT" {
				t.Fatalf("leftover=%q error=%v", left, err)
			}
		})
	}
}

func TestReadResponseHead(t *testing.T) {
	tests := map[string]struct {
		line, reason string
		code         int
		invalid      bool
	}{
		"integer digit limit": {line: "HTTP/1.1 " + strings.Repeat("0", 4301) + " OK", invalid: true},
		"normal":              {line: "HTTP/1.1 200 OK", code: 200, reason: "OK"},
		"empty reason":        {line: "HTTP/1.1 200", code: 200},
		"teapot":              {line: "HTTP/1.1 418 I'm a teapot", code: 418, reason: "I'm a teapot"},
		"non ASCII":           {line: "HTTP/1.1 200 Non-Autoris\xc3\xa9", code: 200, reason: "Non-Autoris\xc3\xa9"},
		"reason whitespace":   {line: "HTTP/1.1 200  two\twords  ", code: 200, reason: "two\twords  "},
		"Python integer":      {line: "HTTP/1.1 +0_200 OK", code: 200, reason: "OK"},
		"missing status":      {line: "HTTP/1.1", invalid: true},
		"invalid status":      {line: "HTTP/1.1 OK OK", invalid: true},
		"invalid underscore":  {line: "HTTP/1.1 20__0 OK", invalid: true},
		"invalid version":     {line: "WTF/1.1 200 OK", invalid: true},
		"empty":               {invalid: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			wire := tt.line + "\r\nContent-Length: 4\r\n\r\n"
			head, err := ReadResponseHead(bufio.NewReader(iotest.OneByteReader(strings.NewReader(wire))))
			if tt.invalid {
				if err == nil {
					t.Fatal("malformed response accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := &httpmsg.Response{StatusCode: tt.code, Reason: tt.reason, HTTPVersion: "HTTP/1.1", Headers: httpmsg.Headers{{Name: []byte("Content-Length"), Value: []byte("4")}}}
			head.Response.TimestampStart = 0
			if diff := gocmp.Diff(want, head.Response); diff != "" {
				t.Fatalf("response (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReadHeaders(t *testing.T) {
	tests := map[string]struct {
		lines   []string
		want    httpmsg.Headers
		invalid bool
	}{
		"simple":              {lines: []string{"Header: one\r\n", "Header2: two\r\n"}, want: httpmsg.Headers{{Name: []byte("Header"), Value: []byte("one")}, {Name: []byte("Header2"), Value: []byte("two")}}},
		"multi":               {lines: []string{"Header: one", "Header: two"}, want: httpmsg.Headers{{Name: []byte("Header"), Value: []byte("one")}, {Name: []byte("Header"), Value: []byte("two")}}},
		"continued":           {lines: []string{"Header: one\r\n", "\ttwo\r\n", "Header2: three\r\n"}, want: httpmsg.Headers{{Name: []byte("Header"), Value: []byte("one\r\n two")}, {Name: []byte("Header2"), Value: []byte("three")}}},
		"continued error":     {lines: []string{"\tfoo: bar\r\n"}, invalid: true},
		"no colon":            {lines: []string{"foo"}, invalid: true},
		"empty name":          {lines: []string{":foo"}, invalid: true},
		"empty value":         {lines: []string{"bar:"}, want: httpmsg.Headers{{Name: []byte("bar"), Value: []byte{}}}},
		"space before colon":  {lines: []string{"X : \v\xff\f "}, want: httpmsg.Headers{{Name: []byte("X "), Value: []byte{0xff}}}},
		"obs-fold Set-Cookie": {lines: []string{"Set-Cookie: x=y;", "\tSecure", "Set-Cookie: a=b"}, want: httpmsg.Headers{{Name: []byte("Set-Cookie"), Value: []byte("x=y;\r\n Secure")}, {Name: []byte("Set-Cookie"), Value: []byte("a=b")}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			lines := make([][]byte, len(tt.lines))
			for i, s := range tt.lines {
				lines[i] = []byte(s)
			}
			got, err := ReadHeaders(lines)
			if tt.invalid {
				if !errors.Is(err, ErrInvalidHead) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("headers (-want +got):\n%s", diff)
			}
			for _, line := range lines {
				clear(line)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("headers alias input: %s", diff)
			}
		})
	}
}

func TestHeadBoundsAndTruncation(t *testing.T) {
	tests := map[string]struct {
		wire string
		want error
	}{
		"empty":              {want: io.EOF},
		"truncated line":     {wire: "GET / HTTP/1.1", want: io.ErrUnexpectedEOF},
		"missing terminator": {wire: "GET / HTTP/1.1\r\nX: y\r\n", want: io.ErrUnexpectedEOF},
		"line cap":           {wire: "GET /" + strings.Repeat("x", MaxLineBytes) + " HTTP/1.1\r\n\r\n", want: ErrLineTooLong},
		"head cap":           {wire: "GET / HTTP/1.1\r\n" + strings.Repeat("X: "+strings.Repeat("x", 1000)+"\r\n", 1100) + "\r\n", want: ErrHeadTooLarge},
		"field cap":          {wire: "GET / HTTP/1.1\r\n" + strings.Repeat("X: y\r\n", MaxHeaderFields+1) + "\r\n", want: ErrTooManyHeaders},
		"leading blank cap":  {wire: strings.Repeat("\n", MaxHeadBytes+1), want: ErrHeadTooLarge},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ReadRequestHead(bufio.NewReader(strings.NewReader(tt.wire)))
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v, got %v", tt.want, err)
			}
		})
	}
	t.Run("leading blanks and bare LF", func(t *testing.T) {
		wire := "\n\r\nGET / HTTP/1.1\nX:y\n\n"
		head, err := ReadRequestHead(bufio.NewReader(strings.NewReader(wire)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(head.Raw, []byte(wire)) || head.Consumed != len(wire) {
			t.Fatalf("head=%+v", head)
		}
	})
}
