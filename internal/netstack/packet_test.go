// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"bytes"
	"errors"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// These vectors port receive_icmp4_echo and receive_icmp6_echo from network/tests.rs.
func TestICMPEcho(t *testing.T) {
	tests := map[string]struct {
		src, dst netip.Addr
		offset   int
		reply    byte
	}{
		"receive_icmp4_echo": {src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.42"), offset: 20, reply: 0},
		"receive_icmp6_echo": {src: netip.MustParseAddr("ca:fe:ca:fe:ca:fe:0:1"), dst: netip.MustParseAddr("ca:fe:ca:fe:ca:fe:0:2"), offset: 40, reply: 129},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			packet := echoPacket(tt.src, tt.dst)
			if err := s.Inject(packet, nil); err != nil {
				t.Fatal(err)
			}
			clear(packet)
			reply := receiveOutbound(t, s)
			if reply[tt.offset] != tt.reply || !bytes.Equal(reply[tt.offset+4:], append([]byte{0, 42, 0x7a, 0x69}, []byte("hello world!")...)) {
				t.Fatalf("echo reply = %x", reply)
			}
			if tt.src.Is4() {
				ip := header.IPv4(reply)
				if ip.SourceAddress() != tcpip.AddrFrom4(tt.dst.As4()) || ip.DestinationAddress() != tcpip.AddrFrom4(tt.src.As4()) || !ip.IsChecksumValid() {
					t.Fatalf("invalid IPv4 reply: %x", reply)
				}
				if checksum.Checksum(reply[20:], 0) != 0xffff {
					t.Fatal("invalid ICMPv4 checksum")
				}
			} else {
				ip := header.IPv6(reply)
				if ip.SourceAddress() != tcpip.AddrFrom16(tt.dst.As16()) || ip.DestinationAddress() != tcpip.AddrFrom16(tt.src.As16()) {
					t.Fatalf("invalid IPv6 reply: %x", reply)
				}
				icmp := header.ICMPv6(reply[40:])
				if got := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: ip.SourceAddress(), Dst: ip.DestinationAddress()}); got != icmp.Checksum() {
					t.Fatal("invalid ICMPv6 checksum")
				}
			}
		})
	}
}

func echoPacket(src, dst netip.Addr) []byte {
	payload := append([]byte{8, 0, 0, 0, 0, 42, 0x7a, 0x69}, []byte("hello world!")...)
	if src.Is4() {
		icmp := header.ICMPv4(payload)
		icmp.SetChecksum(^checksum.Checksum(payload, 0))
		packet := make([]byte, 20+len(payload))
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 255, Protocol: 1, SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4())})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(packet[20:], payload)
		return packet
	}
	payload[0] = 128
	icmp := header.ICMPv6(payload)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: tcpip.AddrFrom16(src.As16()), Dst: tcpip.AddrFrom16(dst.As16())}))
	packet := make([]byte, 40+len(payload))
	header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: uint16(len(payload)), TransportProtocol: 58, HopLimit: 255, SrcAddr: tcpip.AddrFrom16(src.As16()), DstAddr: tcpip.AddrFrom16(dst.As16())})
	copy(packet[40:], payload)
	return packet
}

func receiveOutbound(t *testing.T, s *Stack) []byte {
	t.Helper()
	select {
	case p, ok := <-s.Outbound():
		if !ok {
			t.Fatal("stack stopped before emitting packet")
		}
		return p
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("packet hang detector fired:\n%s", buf[:n])
		return nil
	}
}

func TestInjectOwnershipAndCapacity(t *testing.T) {
	tests := map[string]struct{ count int }{
		"copied packet": {count: 1},
		"bounded queue": {count: packetQueueSize},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Admission is tested without a consumer to make queue exhaustion deterministic.
			s := &Stack{ctx: t.Context(), input: make(chan inboundPacket, packetQueueSize)}
			packet := echoPacket(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.42"))
			want := bytes.Clone(packet)
			meta := []byte("source")
			for range tt.count {
				if err := s.Inject(packet, map[string]any{"tag": meta}); err != nil {
					t.Fatal(err)
				}
			}
			if tt.count == packetQueueSize {
				if err := s.Inject(packet, nil); !errors.Is(err, ErrQueueFull) {
					t.Fatalf("full queue = %v", err)
				}
			}
			clear(packet)
			clear(meta)
			got := <-s.input
			if !bytes.Equal(got.bytes, want) || !bytes.Equal(got.extraInfo["tag"].([]byte), []byte("source")) {
				t.Fatal("Inject retained caller-owned bytes")
			}
		})
	}
}
