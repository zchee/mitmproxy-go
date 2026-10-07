// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"net/netip"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestLoopbackPacketDestinations(t *testing.T) {
	tests := map[string]struct {
		source, destination netip.Addr
	}{
		"IPv4 loopback destination": {source: netip.MustParseAddr("10.0.0.1"), destination: netip.MustParseAddr("127.0.0.1")},
		"IPv6 loopback destination": {source: netip.MustParseAddr("fd00::1"), destination: netip.MustParseAddr("::1")},
		"IPv4 loopback source":      {source: netip.MustParseAddr("127.0.0.1"), destination: netip.MustParseAddr("10.0.0.42")},
		"IPv6 loopback source":      {source: netip.MustParseAddr("::1"), destination: netip.MustParseAddr("fd00::42")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			source := netip.AddrPortFrom(tt.source, 1234)
			destination := netip.AddrPortFrom(tt.destination, 31337)
			if err := s.Inject(udpTestPacket(source, destination, []byte("loopback")), nil); err != nil {
				t.Fatal(err)
			}
			// The subsequent echo response proves the prior admission was processed.
			if err := s.Inject(echoPacket(tt.source, tt.destination), nil); err != nil {
				t.Fatal(err)
			}
			_ = receiveOutbound(t, s)
			select {
			case transport := <-s.UDPConns():
				if transport == nil {
					t.Fatal("stack closed before loopback acceptance")
				}
				if diff := gocmp.Diff(destination.String(), transport.LocalAddr().String()); diff != "" {
					t.Fatal(diff)
				}
				if diff := gocmp.Diff(source.String(), transport.RemoteAddr().String()); diff != "" {
					t.Fatal(diff)
				}
				buf := make([]byte, 64)
				n, _, err := transport.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff("loopback", string(buf[:n])); diff != "" {
					t.Fatal(diff)
				}
				if err := transport.Close(); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("loopback packet did not publish a UDP transport")
			}
		})
	}
}
