// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

func TestServerShutdown(t *testing.T) {
	cfg, err := LoadConfig("../../testdata/wg-test-client/test.conf")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		host   string
		cancel bool
	}{
		"success: explicit close IPv4":       {host: "127.0.0.1"},
		"success: context cancellation IPv6": {host: "::1", cancel: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			stack, err := netstack.New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stack.Close() }()
			socket, err := net.ListenPacket("udp", net.JoinHostPort(test.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			server, err := New(ctx, socket, cfg, stack, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			bound := server.Addr().(*net.UDPAddr)
			bound.Port = 1
			bound.IP[0] ^= 0xff
			if server.Addr().String() != socket.LocalAddr().String() {
				t.Error("Addr exposed mutable listener storage")
			}
			settings, err := server.engine.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			peers, ipv4, ipv6 := 0, false, false
			for line := range strings.SplitSeq(settings, "\n") {
				if strings.HasPrefix(line, "public_key=") {
					peers++
				}
				ipv4 = ipv4 || line == "allowed_ip=0.0.0.0/0"
				ipv6 = ipv6 || line == "allowed_ip=::/0"
			}
			if peers != 1 || !ipv4 || !ipv6 {
				t.Fatal("server did not configure exactly one peer with both default routes")
			}
			if test.cancel {
				cancel()
				waitCtx, waitCancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer waitCancel()
				select {
				case <-server.Done():
				case <-waitCtx.Done():
					deviceTestTimeout(t, waitCtx)
				}
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-server.Done():
			default:
				t.Fatal("Close returned before all server workers finished")
			}
			if err := socket.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
				t.Errorf("consumed socket error=%v, want net.ErrClosed", err)
			}
			packet := serverTestEchoPacket(netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("10.9.8.7"))
			if err := stack.Inject(packet, nil); err != nil {
				t.Fatalf("server closed caller-owned stack: %v", err)
			}
		})
	}
}

func TestServerConsumesFailureSocket(t *testing.T) {
	cfg, err := LoadConfig("../../testdata/wg-test-client/test.conf")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		invalidServerKey bool
		invalidClientKey bool
		nilStack         bool
		cancel           bool
		closedSocket     bool
	}{
		"error: invalid server key": {invalidServerKey: true},
		"error: invalid client key": {invalidClientKey: true},
		"error: nil stack":          {nilStack: true},
		"error: cancelled context":  {cancel: true},
		"error: closed socket":      {closedSocket: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			stack, err := netstack.New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stack.Close() }()
			argument := stack
			if test.nilStack {
				argument = nil
			}
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			if test.closedSocket {
				if err := socket.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancel {
				cancel()
			}
			input := cfg
			if test.invalidServerKey {
				input.ServerKey = "invalid"
			}
			if test.invalidClientKey {
				input.ClientKey = "invalid"
			}
			server, err := New(ctx, socket, input, argument, nil)
			if err == nil {
				_ = server.Close()
				t.Fatal("invalid server construction succeeded")
			}
			if test.cancel && !errors.Is(err, context.Canceled) {
				t.Errorf("cancelled constructor error=%v", err)
			}
			if test.invalidServerKey || test.invalidClientKey {
				if !errors.Is(err, errInvalidKey) {
					t.Errorf("invalid key error=%v", err)
				}
			}
			if err := socket.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
				t.Errorf("failed constructor retained its socket: %v", err)
			}
			packet := serverTestEchoPacket(netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("10.9.8.7"))
			if err := stack.Inject(packet, nil); err != nil {
				t.Fatalf("failed constructor closed caller-owned stack: %v", err)
			}
		})
	}
}

func serverTestEchoPacket(dst, src netip.Addr) []byte {
	if src.Is4() {
		packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
		icmp := header.ICMPv4(packet[header.IPv4MinimumSize:])
		icmp.SetType(header.ICMPv4Echo)
		icmp.SetChecksum(^checksum.Checksum(icmp, 0))
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: 1, SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4())})
		ip.SetChecksum(^ip.CalculateChecksum())
		return packet
	}
	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
	icmp := header.ICMPv6(packet[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6EchoRequest)
	source, destination := tcpip.AddrFrom16(src.As16()), tcpip.AddrFrom16(dst.As16())
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: source, Dst: destination}))
	header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: uint16(len(icmp)), TransportProtocol: 58, HopLimit: 64, SrcAddr: source, DstAddr: destination})
	return packet
}
