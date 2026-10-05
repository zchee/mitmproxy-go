// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/zchee/mitmproxy-go/tlsparse"
)

// fuzzSeeds are the wire-format corpus shared by both fuzz targets: the
// upstream single-record and split-record hellos, truncations, lying
// lengths and plain garbage.
func fuzzSeeds(f *testing.F) {
	f.Helper()
	hs := handshakeNoExtensions(f)
	f.Add([]byte{})
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add(mustHex(f, "1603010000"))
	f.Add(mustHex(f, "16030100"))
	f.Add(cat(mustHex(f, "1603010065"), hs))
	f.Add(cat(mustHex(f, "1603010020"), hs[:32], mustHex(f, "1603010045"), hs[32:]))
	f.Add(recordWithExtensions(f))
	f.Add(recordWithExtensions(f)[:50])
	f.Add(cat(mustHex(f, "16030300bb0100ffb7"), mustHex(f, clientHelloExtensions)))
	f.Add(mustHex(f, "160303000401ffffff"))
	f.Add(inRecords([]byte{0x01, 0x00, 0x01, 0xff}, 1))
}

func FuzzGetClientHello(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := tlsparse.GetClientHello(data)
		if err != nil {
			if msg != nil {
				t.Fatalf("GetClientHello returned both a message and %v", err)
			}
			return
		}
		if msg == nil {
			return
		}
		if len(msg) < 4 || len(msg) > tlsparse.MaxClientHelloSize {
			t.Fatalf("GetClientHello returned %d bytes, want 4 to %d", len(msg), tlsparse.MaxClientHelloSize)
		}
		declared := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
		if len(msg) != declared+4 {
			t.Fatalf("GetClientHello returned %d bytes for a declared length of %d", len(msg), declared)
		}
		// Reassembly must be deterministic, and feeding more than the
		// message must not change it.
		again, err := tlsparse.GetClientHello(data)
		if err != nil || !bytes.Equal(msg, again) {
			t.Fatalf("second GetClientHello = %x, %v; want the same message", again, err)
		}
	})
}

func FuzzParseClientHello(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		ch, err := tlsparse.ParseClientHello(data)
		if err != nil || ch == nil {
			return
		}
		// The accessors must hold for whatever parsed: the raw body
		// round-trips, and the parsed hello reparses to the same values.
		raw := ch.RawBytes(false)
		again, err := tlsparse.NewClientHello(raw)
		if err != nil {
			t.Fatalf("NewClientHello(RawBytes()): %v", err)
		}
		if ch.SNI() != again.SNI() {
			t.Fatalf("SNI %q changed to %q on reparse", ch.SNI(), again.SNI())
		}
		if a, b := ch.ALPNProtocols(), again.ALPNProtocols(); !slices.EqualFunc(a, b, bytes.Equal) {
			t.Fatalf("ALPNProtocols %q changed to %q on reparse", a, b)
		}
		if a, b := ch.CipherSuites(), again.CipherSuites(); !slices.Equal(a, b) {
			t.Fatalf("CipherSuites %v changed to %v on reparse", a, b)
		}
		if ch.String() == "" {
			t.Fatal("String() is empty")
		}
	})
}
