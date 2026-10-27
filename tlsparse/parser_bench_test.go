// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse_test

import (
	"testing"

	"github.com/zchee/mitmproxy-go/tlsparse"
)

func BenchmarkTLSClientHello(b *testing.B) {
	// These are the pinned upstream ClientHello bodies also used by the parser tests.
	vectors := [][]byte{mustHex(b, clientHelloNoExtensions), mustHex(b, clientHelloExtensions), {3, 3, 0}}
	var size int64
	for _, wire := range vectors {
		size += int64(len(wire))
	}
	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		for i, wire := range vectors {
			hello, err := tlsparse.NewClientHello(wire)
			if i == 2 {
				if err == nil {
					b.Fatal("truncated ClientHello accepted")
				}
			} else if err != nil || len(hello.CipherSuites()) == 0 {
				b.Fatalf("ClientHello %d: %v", i, err)
			}
		}
	}
}
