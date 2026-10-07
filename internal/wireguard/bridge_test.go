// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

func TestServerEncryptedIPBridge(t *testing.T) {
	cfg, err := LoadConfig("../../testdata/wg-test-client/test.conf")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		host                string
		source, destination netip.Addr
	}{
		"success: arbitrary IPv4 source": {host: "127.0.0.1", source: netip.MustParseAddr("10.9.8.7"), destination: netip.MustParseAddr("198.51.100.7")},
		"success: arbitrary IPv6 source": {host: "::1", source: netip.MustParseAddr("2001:db8::17"), destination: netip.MustParseAddr("2001:db8::42")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			stack, err := netstack.New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stack.Close() }()
			socket, err := net.ListenPacket("udp", net.JoinHostPort(test.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			server, err := New(ctx, socket, cfg, stack, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			clientKey, err := privateKey(cfg.ClientKey)
			if err != nil {
				t.Fatal(err)
			}
			serverKey, err := privateKey(cfg.ServerKey)
			if err != nil {
				t.Fatal(err)
			}
			clientTUN := tuntest.NewChannelTUN()
			client := newDevice(clientTUN.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
			defer client.Close()
			settings := "private_key=" + hex.EncodeToString(clientKey.Bytes()) + "\npublic_key=" + hex.EncodeToString(serverKey.PublicKey().Bytes()) + "\nendpoint=" + server.Addr().String() + "\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"
			if err := client.IpcSet(settings); err != nil {
				t.Fatalf("configure encrypted peer: %v", err)
			}
			if err := client.Up(); err != nil {
				t.Fatal(err)
			}
			packet := serverTestEchoPacket(test.destination, test.source)
			select {
			case clientTUN.Outbound <- packet:
			case <-ctx.Done():
				deviceTestTimeout(t, ctx)
			}
			var reply []byte
			select {
			case reply = <-clientTUN.Inbound:
			case <-ctx.Done():
				deviceTestTimeout(t, ctx)
			}
			if test.source.Is4() {
				if len(reply) < header.IPv4MinimumSize+header.ICMPv4MinimumSize {
					t.Fatal("truncated encrypted IPv4 echo reply")
				}
				ip := header.IPv4(reply)
				if ip.SourceAddress() != tcpip.AddrFrom4(test.destination.As4()) || ip.DestinationAddress() != tcpip.AddrFrom4(test.source.As4()) || !ip.IsChecksumValid() || header.ICMPv4(reply[20:]).Type() != header.ICMPv4EchoReply {
					t.Fatal("incorrect decrypted IPv4 echo reply")
				}
			} else {
				if len(reply) < header.IPv6MinimumSize+header.ICMPv6MinimumSize {
					t.Fatal("truncated encrypted IPv6 echo reply")
				}
				ip := header.IPv6(reply)
				if ip.SourceAddress() != tcpip.AddrFrom16(test.destination.As16()) || ip.DestinationAddress() != tcpip.AddrFrom16(test.source.As16()) || header.ICMPv6(reply[40:]).Type() != header.ICMPv6EchoReply {
					t.Fatal("incorrect decrypted IPv6 echo reply")
				}
			}
		})
	}
}
