// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

// TestServerMultiPeerRouting is a behavioural regression: the contract parent
// rejects the multi-key configuration instead of serving both encrypted peers.
// The sequence exercises IPv4/IPv6 learning, reassignment and first-peer fallback
// through the real stack and encrypted devices, not a synthetic routing map.
func TestServerMultiPeerRouting(t *testing.T) {
	legacy, err := LoadConfig("../../testdata/wg-test-client/test.conf")
	if err != nil {
		t.Fatal(err)
	}
	const secondKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	tests := map[string]struct {
		first, second, moved, unknown, destination netip.Addr
	}{
		"success: IPv4 source ownership": {
			first: netip.MustParseAddr("10.9.8.7"), second: netip.MustParseAddr("10.9.8.8"),
			moved: netip.MustParseAddr("10.9.8.9"), unknown: netip.MustParseAddr("10.9.8.10"), destination: netip.MustParseAddr("198.51.100.7"),
		},
		"success: IPv6 source ownership": {
			first: netip.MustParseAddr("2001:db8::1"), second: netip.MustParseAddr("2001:db8::2"),
			moved: netip.MustParseAddr("2001:db8::3"), unknown: netip.MustParseAddr("2001:db8::4"), destination: netip.MustParseAddr("2001:db8::42"),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()
			t.Cleanup(func() { goleak.VerifyNone(t, ignore) })
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			stack, err := netstack.New(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stack.Close() }()
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			configuration := Config{ServerKey: legacy.ServerKey, ClientKeys: []string{legacy.ClientKey, secondKey}}
			server, err := New(ctx, socket, configuration, stack, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("start multi-peer server: %v", err)
			}
			defer func() { _ = server.Close() }()
			clients := []*tuntest.ChannelTUN{
				newRoutingClient(t, legacy.ServerKey, legacy.ClientKey, server.Addr().String()),
				newRoutingClient(t, legacy.ServerKey, secondKey, server.Addr().String()),
			}
			sequence := []struct {
				peer   int
				source netip.Addr
			}{
				{peer: 0, source: test.first},
				{peer: 1, source: test.second},
				{peer: 1, source: test.moved},
				{peer: 0, source: test.moved},
			}
			for _, step := range sequence {
				packet := serverTestEchoPacket(test.destination, step.source)
				select {
				case clients[step.peer].Outbound <- packet:
				case <-ctx.Done():
					deviceTestTimeout(t, ctx)
				}
				assertRoutingReply(t, ctx, clients, step.peer, test.destination, step.source)
			}
			// No peer has used this source; the first configured peer gets its reply.
			if err := stack.Inject(serverTestEchoPacket(test.destination, test.unknown), nil); err != nil {
				t.Fatal(err)
			}
			assertRoutingReply(t, ctx, clients, 0, test.destination, test.unknown)
			// Changing address did not forget the second peer's original source.
			if err := stack.Inject(serverTestEchoPacket(test.destination, test.second), nil); err != nil {
				t.Fatal(err)
			}
			assertRoutingReply(t, ctx, clients, 1, test.destination, test.second)
		})
	}
}

func newRoutingClient(t *testing.T, serverText, clientText, endpoint string) *tuntest.ChannelTUN {
	t.Helper()
	serverKey, err := privateKey(serverText)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := privateKey(clientText)
	if err != nil {
		t.Fatal(err)
	}
	var private device.NoisePrivateKey
	if err := private.FromHex(hex.EncodeToString(clientKey.Bytes())); err != nil {
		t.Fatal(err)
	}
	tunnel := tuntest.NewChannelTUN()
	engine := newDevice(tunnel.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(engine.Close)
	configuration := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", hex.EncodeToString(private[:]), hex.EncodeToString(serverKey.PublicKey().Bytes()), endpoint)
	if err := engine.IpcSet(configuration); err != nil {
		t.Fatal(err)
	}
	if err := engine.Up(); err != nil {
		t.Fatal(err)
	}
	return tunnel
}

func assertRoutingReply(t *testing.T, ctx context.Context, clients []*tuntest.ChannelTUN, peer int, source, destination netip.Addr) {
	t.Helper()
	select {
	case packet := <-clients[peer].Inbound:
		var gotSource, gotDestination netip.Addr
		if destination.Is4() && len(packet) >= header.IPv4MinimumSize {
			ip := header.IPv4(packet)
			gotSource = netip.AddrFrom4(ip.SourceAddress().As4())
			gotDestination = netip.AddrFrom4(ip.DestinationAddress().As4())
		} else if destination.Is6() && len(packet) >= header.IPv6MinimumSize {
			ip := header.IPv6(packet)
			gotSource = netip.AddrFrom16(ip.SourceAddress().As16())
			gotDestination = netip.AddrFrom16(ip.DestinationAddress().As16())
		}
		if diff := gocmp.Diff([]string{source.String(), destination.String()}, []string{gotSource.String(), gotDestination.String()}); diff != "" {
			t.Fatalf("peer %d reply addresses (-want +got):\n%s", peer, diff)
		}
	case packet := <-clients[1-peer].Inbound:
		t.Fatalf("reply reached wrong encrypted peer: expected peer %d, got %d (%d bytes)", peer, 1-peer, len(packet))
	case <-ctx.Done():
		deviceTestTimeout(t, ctx)
	}
}
