// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"bytes"
	"errors"
	"testing"
)

func BenchmarkReadRequest(b *testing.B) {
	vectors := [][]byte{
		[]byte("GET /search?q=proxy HTTP/1.1\r\nHost: example.test\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, br\r\nUser-Agent: mitmproxy-go\r\n\r\n"),
		[]byte("POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/octet-stream\r\nContent-Length: 1048576\r\nX-Binary: \x80\xff\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\nMissing-Colon\r\n\r\n"),
	}
	reader := bytes.NewReader(nil)
	buffered := bufio.NewReader(reader)
	var size int64
	for _, wire := range vectors {
		size += int64(len(wire))
	}
	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		for i, wire := range vectors {
			reader.Reset(wire)
			buffered.Reset(reader)
			head, err := ReadRequestHead(buffered)
			if i == 2 {
				if !errors.Is(err, ErrInvalidHead) {
					b.Fatalf("malformed request: %v", err)
				}
			} else if err != nil || head.Consumed != len(wire) || len(head.Request.Headers) == 0 {
				b.Fatalf("request %d: consumed=%d error=%v", i, head.Consumed, err)
			}
		}
	}
}

func BenchmarkReadResponse(b *testing.B) {
	vectors := [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1048576\r\nCache-Control: public, max-age=3600\r\nETag: \"proxy-body\"\r\n\r\n"),
		[]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nX-Binary: \x80\xff\r\n\r\n"),
		[]byte("HTTP/1.1 invalid status\r\n\r\n"),
	}
	reader := bytes.NewReader(nil)
	buffered := bufio.NewReader(reader)
	var size int64
	for _, wire := range vectors {
		size += int64(len(wire))
	}
	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		for i, wire := range vectors {
			reader.Reset(wire)
			buffered.Reset(reader)
			head, err := ReadResponseHead(buffered)
			if i == 2 {
				if !errors.Is(err, ErrInvalidHead) {
					b.Fatalf("malformed response: %v", err)
				}
			} else if err != nil || head.Consumed != len(wire) || head.Response.StatusCode < 200 {
				b.Fatalf("response %d: consumed=%d error=%v", i, head.Consumed, err)
			}
		}
	}
}
