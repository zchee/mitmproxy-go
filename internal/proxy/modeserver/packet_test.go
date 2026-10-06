// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"net"
	"strings"
	"testing"
)

// Upstream UDP listener lifecycle and bind-error cases use real sockets.
func TestPacketStartStop(t *testing.T) {
	tests := map[string]struct{ scheme string }{
		"UDP":  {scheme: "udp"},
		"DTLS": {scheme: "dtls"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			instance := makeInstance(t, "reverse:"+test.scheme+"://127.0.0.1:443@127.0.0.1:0", cfg)
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			addr := instance.ListenAddrs()[0]
			if addr.Port == 0 || !instance.IsRunning() {
				t.Fatal("bound UDP address not published")
			}
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
				t.Fatal("packet listener remains published")
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			rebound, err := net.ListenPacket("udp", addr.String())
			if err != nil {
				t.Fatalf("packet listener not released: %v", err)
			}
			if err := rebound.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := instance.Start(ctx); err == nil {
				_ = instance.Stop()
				t.Fatal("started after context cancellation")
			}
		})
	}
}

func TestPacketStartError(t *testing.T) {
	cfg, _, _ := fixture(t)
	occupied, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	instance := makeInstance(t, "reverse:udp://127.0.0.1:443@"+occupied.LocalAddr().String(), cfg)
	if err := instance.Start(t.Context()); err == nil || !strings.Contains(err.Error(), "failed to listen") {
		t.Fatalf("packet bind error = %v", err)
	}
	if instance.IsRunning() || instance.LastError() == nil {
		t.Fatal("packet bind failure not published")
	}
}
