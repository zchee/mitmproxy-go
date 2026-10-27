// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"encoding/hex"
	"testing"
)

func BenchmarkDNSUnpack(b *testing.B) {
	// Query and compressed binary answers are pinned upstream test_packing vectors.
	hexVectors := []string{
		"002a0100000100000000000003646e7306676f6f676c650000010001",
		"002a8180000100020000000003646e7306676f6f676c650000010001c00c0001000100000020000408080808c00c0001000100000020000408080404",
		"002a01000001000000000000c00c00010001",
	}
	vectors := make([][]byte, len(hexVectors))
	var size int64
	for i, text := range hexVectors {
		wire, err := hex.DecodeString(text)
		if err != nil {
			b.Fatal(err)
		}
		vectors[i] = wire
		size += int64(len(wire))
	}
	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		for i, wire := range vectors {
			message, err := Unpack(wire, nil)
			if i == 2 {
				if err == nil {
					b.Fatal("compression loop accepted")
				}
			} else if err != nil || message.ID != 42 || len(message.Questions) != 1 {
				b.Fatalf("DNS vector %d: %v", i, err)
			}
		}
	}
}
