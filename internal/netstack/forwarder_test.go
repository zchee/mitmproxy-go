// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestUDPForwarderPorts(t *testing.T) {
	tests := map[string]struct{ src, dst netip.AddrPort }{
		"ipv4_udp": {src: netip.MustParseAddrPort("10.0.0.1:1234"), dst: netip.MustParseAddrPort("10.0.0.42:31337")},
		"ipv6_udp": {src: netip.MustParseAddrPort("[ca:fe:ca:fe:ca:fe:0:1]:1234"), dst: netip.MustParseAddrPort("[ca:fe:ca:fe:ca:fe:0:2]:31337")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			info := map[string]any{"original_src": netip.MustParseAddrPort("192.168.86.134:12345"), "original_dst": netip.MustParseAddrPort("0.0.0.0:0"), "pid": uint32(42), "process_name": "curl", "remote_endpoint": "example.test:443"}
			if err := s.Inject(udpTestPacket(tt.src, tt.dst, []byte("hello world!")), info); err != nil {
				t.Fatal(err)
			}
			var transport interface {
				ReadFrom([]byte) (int, net.Addr, error)
				WriteTo([]byte, net.Addr) (int, error)
				RemoteAddr() net.Addr
				LocalAddr() net.Addr
				GetExtraInfo(string) (any, bool)
				Close() error
			}
			select {
			case p := <-s.UDPConns():
				transport = p.(interface {
					ReadFrom([]byte) (int, net.Addr, error)
					WriteTo([]byte, net.Addr) (int, error)
					RemoteAddr() net.Addr
					LocalAddr() net.Addr
					GetExtraInfo(string) (any, bool)
					Close() error
				})
			case <-time.After(30 * time.Second):
				t.Fatal("UDP accept hang detector")
			}
			if transport.RemoteAddr().String() != tt.src.String() || transport.LocalAddr().String() != tt.dst.String() {
				t.Fatalf("tuple = %v -> %v", transport.RemoteAddr(), transport.LocalAddr())
			}
			for key, want := range info {
				got, ok := transport.GetExtraInfo(key)
				if !ok || !gocmp.Equal(want, got, gocmp.Comparer(func(a, b netip.AddrPort) bool { return a == b })) {
					t.Fatalf("metadata %s = %v, want %v", key, got, want)
				}
			}
			buf := make([]byte, 64)
			n, _, err := transport.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "hello world!" {
				t.Fatalf("UDP read = %q, %v", buf[:n], err)
			}
			if _, err := transport.WriteTo([]byte("HELLO WORLD!"), transport.RemoteAddr()); err != nil {
				t.Fatal(err)
			}
			reply := receiveOutbound(t, s)
			off := 20
			if tt.src.Addr().Is6() {
				off = 40
			}
			if string(reply[off+8:]) != "HELLO WORLD!" {
				t.Fatalf("UDP reply = %x", reply)
			}
			if err := transport.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUDPExpiryClock(t *testing.T) {
	tests := map[string]struct{ refresh bool }{"expires at sixty seconds": {}, "incoming refresh": {refresh: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			s, err := newStack(t.Context(), clock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			src := netip.MustParseAddrPort("10.0.0.1:1234")
			dst := netip.MustParseAddrPort("10.0.0.42:31337")
			if err := s.Inject(udpTestPacket(src, dst, []byte("one")), nil); err != nil {
				t.Fatal(err)
			}
			var p layer.PacketTransport
			select {
			case accepted := <-s.UDPConns():
				p = accepted
			case <-time.After(30 * time.Second):
				t.Fatal("UDP accept hang detector")
			}
			buf := make([]byte, 8)
			if _, _, err := p.ReadFrom(buf); err != nil {
				t.Fatal(err)
			}
			clock.Advance(59 * time.Second)
			if p.Context().Err() != nil {
				t.Fatal("UDP expired early")
			}
			if tt.refresh {
				if err := s.Inject(udpTestPacket(src, dst, []byte("two")), nil); err != nil {
					t.Fatal(err)
				}
				if _, _, err := p.ReadFrom(buf); err != nil {
					t.Fatal(err)
				}
				clock.Advance(time.Second)
				if p.Context().Err() != nil {
					t.Fatal("incoming packet did not refresh expiry")
				}
				clock.Advance(59 * time.Second)
			} else {
				clock.Advance(time.Second)
			}
			if p.Context().Err() == nil {
				t.Fatal("UDP did not expire at deadline")
			}
			if _, _, err := p.ReadFrom(buf); err == nil {
				t.Fatal("expired tuple remained readable")
			}
		})
	}
}

func udpTestPacket(src, dst netip.AddrPort, data []byte) []byte {
	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp, src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], data)
	a := tcpip.AddrFromSlice(src.Addr().AsSlice())
	b := tcpip.AddrFromSlice(dst.Addr().AsSlice())
	cs := checksum.Checksum(udp, header.PseudoHeaderChecksum(header.UDPProtocolNumber, a, b, uint16(len(udp))))
	sum := ^cs
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return testIPPacket(src.Addr(), dst.Addr(), 17, udp)
}

func testIPPacket(src, dst netip.Addr, protocol byte, payload []byte) []byte {
	if src.Is4() {
		out := make([]byte, 20+len(payload))
		ip := header.IPv4(out)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(out)), TTL: 255, Protocol: protocol, SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4())})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(out[20:], payload)
		return out
	}
	out := make([]byte, 40+len(payload))
	header.IPv6(out).Encode(&header.IPv6Fields{PayloadLength: uint16(len(payload)), HopLimit: 255, TransportProtocol: tcpip.TransportProtocolNumber(protocol), SrcAddr: tcpip.AddrFrom16(src.As16()), DstAddr: tcpip.AddrFrom16(dst.As16())})
	copy(out[40:], payload)
	return out
}
