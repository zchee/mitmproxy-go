// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"net"
	"net/netip"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestUDPFixedPeerWrites(t *testing.T) {
	tests := map[string]struct {
		address   string
		wantError bool
	}{
		"nil selects fixed peer": {},
		"explicit fixed peer":    {address: "10.0.0.1:1234"},
		"error: different peer":  {address: "10.0.0.2:1234", wantError: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			source := netip.MustParseAddrPort("10.0.0.1:1234")
			destination := netip.MustParseAddrPort("10.0.0.42:31337")
			if err := s.Inject(udpTestPacket(source, destination, []byte("hello")), nil); err != nil {
				t.Fatal(err)
			}
			var transport layer.PacketTransport
			select {
			case transport = <-s.UDPConns():
			case <-time.After(30 * time.Second):
				t.Fatal("UDP accept hang detector")
			}
			if transport == nil {
				t.Fatal("stack stopped before tuple acceptance")
			}
			buf := make([]byte, 64)
			if _, _, err := transport.ReadFrom(buf); err != nil {
				t.Fatal(err)
			}
			var address net.Addr
			if tt.address != "" {
				peer := netip.MustParseAddrPort(tt.address)
				address = &net.UDPAddr{IP: peer.Addr().AsSlice(), Port: int(peer.Port())}
			}
			n, err := transport.WriteTo([]byte("HELLO"), address)
			if tt.wantError {
				if err == nil || n != 0 {
					t.Fatalf("different peer write = %d, %v", n, err)
				}
				select {
				case packet := <-s.Outbound():
					t.Fatalf("rejected write emitted packet: %x", packet)
				default:
				}
				return
			}
			if err != nil || n != len("HELLO") {
				t.Fatalf("fixed peer write = %d, %v", n, err)
			}
			reply := receiveOutbound(t, s)
			if diff := gocmp.Diff("HELLO", string(reply[28:])); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
