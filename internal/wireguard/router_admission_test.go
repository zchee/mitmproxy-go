// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

// TestPacketRouterAdmissionBound reproduces unbounded learned-source growth on
// the parent through the authenticated-plaintext adapter and a real IP stack.
func TestPacketRouterAdmissionBound(t *testing.T) {
	tests := map[string]struct{ source, destination netip.Addr }{
		"success: IPv4 aggregate bound": {source: netip.MustParseAddr("10.1.0.1"), destination: netip.MustParseAddr("198.51.100.7")},
		"success: IPv6 aggregate bound": {source: netip.MustParseAddr("2001:db8::1"), destination: netip.MustParseAddr("2001:db8:1::1")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tunnel, ctx := newRetentionDevice(t)
			source := test.source
			for i := range 4097 {
				tunnel.peer = i % 2
				packet := serverTestEchoPacket(test.destination, source)
				if n, err := tunnel.Write([][]byte{packet}, 0); err != nil || n != 1 {
					t.Fatalf("source %d admission = %d, %v", i, n, err)
				}
				select {
				case <-tunnel.stack.Outbound():
				case <-ctx.Done():
					t.Fatalf("source %d was not admitted: %v", i, ctx.Err())
				}
				if got := len(tunnel.router.sources); got != min(i+1, 4096) {
					t.Fatalf("learned source count after admission %d = %d, want %d", i+1, got, min(i+1, 4096))
				}
				source = source.Next()
			}
			if _, retained := tunnel.router.sources[test.source]; retained {
				t.Fatal("oldest source remained learned after the aggregate bound")
			}
		})
	}
}

func newRetentionDevice(t *testing.T) (*stackDevice, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	stack, err := netstack.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	engine := newDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(engine.Close)
	logger := slog.New(slog.DiscardHandler)
	return &stackDevice{ctx: ctx, cancel: cancel, stack: stack, engine: engine, router: newPacketRouter(2, logger), peer: 1, logger: logger}, ctx
}
