// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"bytes"
	"testing"
)

// benchFlow returns a value shaped like an HTTP flow's state: nested
// dictionaries, header pairs, timestamps and a 4 KiB body.
func benchFlow() *Dict {
	headers := make([]any, 0, 12)
	for _, h := range []string{"Host", "User-Agent", "Accept", "Accept-Encoding", "Content-Type", "Content-Length", "Cookie", "Cache-Control", "Connection", "Referer", "Origin", "X-Request-Id"} {
		headers = append(headers, []any{[]byte(h), []byte("value-of-" + h)})
	}
	message := func(body int) *Dict {
		return dict(
			"http_version", "HTTP/1.1",
			"headers", headers,
			"content", bytes.Repeat([]byte("x"), body),
			"trailers", nil,
			"timestamp_start", 1759600000.123456,
			"timestamp_end", 1759600000.223456,
		)
	}
	conn := dict(
		"id", "4a9d6a54-7c11-4c1e-9b5e-3f7f1c1e8b8a",
		"peername", []any{"127.0.0.1", int64(52344)},
		"sockname", []any{"127.0.0.1", int64(8080)},
		"tls_established", true,
		"timestamp_start", 1759600000.0,
		"alpn_offers", []any{[]byte("h2"), []byte("http/1.1")},
	)
	return dict(
		"version", int64(21),
		"type", "http",
		"id", "5e0bd8f6-3a58-4a39-a6f2-6c39b2e5e3a1",
		"client_conn", conn,
		"server_conn", conn,
		"request", message(512),
		"response", message(4096),
		"metadata", dict(),
		"marked", "",
		"is_replay", nil,
		"comment", "",
		"timestamp_created", 1759600000.0,
		"websocket", nil,
	)
}

func BenchmarkDumps(b *testing.B) {
	v := benchFlow()
	enc, err := Dumps(v)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Dumps(v); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoads(b *testing.B) {
	enc, err := Dumps(benchFlow())
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Loads(enc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFormatFloat(b *testing.B) {
	buf := make([]byte, 0, 32)
	b.ReportAllocs()
	for b.Loop() {
		buf = appendFloat(buf[:0], 1759600000.123456)
	}
}
