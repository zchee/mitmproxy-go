// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack_test

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/internal/netstack"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/wireguard"
)

func TestEncryptedLoopbackDatagram(t *testing.T) {
	tests := map[string]struct{ source, destination netip.Addr }{
		"IPv4 host loopback": {source: netip.MustParseAddr("10.0.0.1"), destination: netip.MustParseAddr("127.0.0.1")},
		"IPv6 host loopback": {source: netip.MustParseAddr("fd00::1"), destination: netip.MustParseAddr("::1")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			configuration, err := wireguard.LoadConfig(filepath.Join(t.TempDir(), "wireguard.conf"))
			if err != nil {
				t.Fatal(err)
			}
			s, err := netstack.New(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server, err := wireguard.New(ctx, socket, configuration, s, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			clientPrivate, err := base64.StdEncoding.DecodeString(configuration.ClientKey)
			if err != nil {
				t.Fatal("invalid generated client key")
			}
			serverPrivate, err := base64.StdEncoding.DecodeString(configuration.ServerKey)
			if err != nil {
				t.Fatal("invalid generated server key")
			}
			key, err := ecdh.X25519().NewPrivateKey(serverPrivate)
			if err != nil {
				t.Fatal("invalid generated server key")
			}
			tunnel := tuntest.NewChannelTUN()
			client := device.NewDevice(tunnel.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
			t.Cleanup(client.Close)
			settings := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", hex.EncodeToString(clientPrivate), hex.EncodeToString(key.PublicKey().Bytes()), server.Addr())
			if err := client.IpcSet(settings); err != nil {
				t.Fatal("configure real encrypted client failed")
			}
			if err := client.Up(); err != nil {
				t.Fatal(err)
			}
			packet := loopbackUDPTestPacket(tt.source, tt.destination, []byte("hello"))
			select {
			case tunnel.Outbound <- packet:
			case <-ctx.Done():
				failEncryptedLoopback(t, ctx.Err())
			}
			var transport layer.PacketTransport
			select {
			case transport = <-s.UDPConns():
			case <-ctx.Done():
				failEncryptedLoopback(t, ctx.Err())
			}
			if transport == nil {
				t.Fatal("stack stopped before encrypted datagram admission")
			}
			if diff := gocmp.Diff(netip.AddrPortFrom(tt.destination, 31337).String(), transport.LocalAddr().String()); diff != "" {
				t.Fatal(diff)
			}
			buf := make([]byte, 64)
			n, _, err := transport.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("hello", string(buf[:n])); diff != "" {
				t.Fatal(diff)
			}
			if _, err := transport.WriteTo([]byte("HELLO"), transport.RemoteAddr()); err != nil {
				t.Fatal(err)
			}
			select {
			case reply := <-tunnel.Inbound:
				offset := 20
				if tt.destination.Is6() {
					offset = 40
				}
				if len(reply) < offset+8 {
					t.Fatalf("truncated encrypted reply: %d bytes", len(reply))
				}
				if diff := gocmp.Diff("HELLO", string(reply[offset+8:])); diff != "" {
					t.Fatal(diff)
				}
			case <-ctx.Done():
				failEncryptedLoopback(t, ctx.Err())
			}
		})
	}
}

func failEncryptedLoopback(t *testing.T, err error) {
	t.Helper()
	stack := make([]byte, 1<<20)
	n := runtime.Stack(stack, true)
	t.Fatalf("encrypted loopback hang detector: %v\n%s", err, stack[:n])
}

func loopbackUDPTestPacket(source, destination netip.Addr, payload []byte) []byte {
	udp := make([]byte, header.UDPMinimumSize+len(payload))
	header.UDP(udp).Encode(&header.UDPFields{SrcPort: 1234, DstPort: 31337, Length: uint16(len(udp))})
	copy(udp[header.UDPMinimumSize:], payload)
	src, dst := tcpip.AddrFromSlice(source.AsSlice()), tcpip.AddrFromSlice(destination.AsSlice())
	cs := ^checksum.Checksum(udp, header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(len(udp))))
	if cs == 0 {
		cs = 0xffff
	}
	header.UDP(udp).SetChecksum(cs)
	if source.Is4() {
		packet := make([]byte, header.IPv4MinimumSize+len(udp))
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: src, DstAddr: dst})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(packet[header.IPv4MinimumSize:], udp)
		return packet
	}
	packet := make([]byte, header.IPv6MinimumSize+len(udp))
	header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: uint16(len(udp)), HopLimit: 64, TransportProtocol: header.UDPProtocolNumber, SrcAddr: src, DstAddr: dst})
	copy(packet[header.IPv6MinimumSize:], udp)
	return packet
}
