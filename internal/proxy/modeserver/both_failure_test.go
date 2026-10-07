// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
)

func TestBothListenerFactoryRollback(t *testing.T) {
	tests := map[string]struct{ spec, scheme string }{
		"standalone DNS": {"dns@127.0.0.1:0", "dns"},
		"reverse HTTPS":  {"reverse:https://example.test@127.0.0.1:0", "https"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			failure := errors.New("factory rejected bound socket")
			var address string
			cfg.ListenerFactories = map[ListenerKey]ListenerFactory{
				{Scheme: tt.scheme, Transport: connection.UDP}: func(_ context.Context, socket net.PacketConn, _ PacketHandler) (io.Closer, error) {
					address = socket.LocalAddr().String()
					return nil, failure
				},
			}
			instance := makeInstance(t, tt.spec, cfg)
			if err := instance.Start(t.Context()); !errors.Is(err, failure) {
				t.Fatalf("Start = %v", err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 || address == "" {
				t.Fatal("failed factory published listeners or was not invoked")
			}
			stream, err := net.Listen("tcp4", address)
			if err != nil {
				t.Fatalf("failed factory retained TCP listener: %v", err)
			}
			defer func() { _ = stream.Close() }()
			packet, err := net.ListenPacket("udp4", address)
			if err != nil {
				t.Fatalf("failed factory retained UDP socket: %v", err)
			}
			defer func() { _ = packet.Close() }()
		})
	}
}

func TestBothListenerDualStack(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	_ = probe.Close()
	packet, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 UDP unavailable: %v", err)
	}
	_ = packet.Close()
	cfg, _, _ := fixture(t)
	instance := makeInstance(t, "dns@0", cfg)
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	state := instance.state.Load()
	if len(state.listeners) != 2 || len(state.packetListeners) != 2 || len(state.addrs) != 4 {
		t.Fatalf("TCP=%d UDP=%d addresses=%v", len(state.listeners), len(state.packetListeners), state.addrs)
	}
	port := state.addrs[0].Port
	for _, address := range state.addrs {
		if port == 0 || address.Port != port {
			t.Fatalf("dual stack transports selected different ports: %v", state.addrs)
		}
	}
	if err := instance.Stop(); err != nil {
		t.Fatal(err)
	}
}
