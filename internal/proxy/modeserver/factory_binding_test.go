// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestBoundPacketFactoryRollback(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	_ = probe.Close()
	tests := map[string]struct {
		failAt    int
		nilCloser bool
	}{
		"first factory":     {0, false},
		"second factory":    {1, false},
		"second nil closer": {1, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			cfg.ListenHost = ""
			instance := makeInstance(t, "reverse:udp://example.test:443@0", cfg)
			calls, port := 0, 0
			want := errors.New("listener setup failed")
			factory := func(_ context.Context, socket net.PacketConn, _ PacketHandler) (io.Closer, error) {
				port = socket.LocalAddr().(*net.UDPAddr).Port
				n := calls
				calls++
				if n == tt.failAt {
					if tt.nilCloser {
						return nil, nil
					}
					return nil, want
				}
				return socket, nil
			}
			listeners, addrs, err := instance.startPacketFactories(t.Context(), 0, factory, func(context.Context, layer.PacketTransport) error { return nil })
			if err == nil || !tt.nilCloser && !errors.Is(err, want) {
				t.Fatalf("start factories = %v", err)
			}
			if len(listeners) != 0 || len(addrs) != 0 || calls != tt.failAt+1 {
				t.Fatalf("failed startup retained state: listeners=%d addrs=%v calls=%d", len(listeners), addrs, calls)
			}
			for _, protocol := range []string{"udp4", "udp6"} {
				host := "0.0.0.0"
				if protocol == "udp6" {
					host = "::"
				}
				socket, err := net.ListenPacket(protocol, net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					t.Fatalf("rollback retained %s socket: %v", protocol, err)
				}
				_ = socket.Close()
			}
		})
	}
}

func TestPacketSocketSharesTCPPort(t *testing.T) {
	cfg, _, _ := fixture(t)
	instance := makeInstance(t, "reverse:udp://example.test:443@127.0.0.1:0", cfg)
	stream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	port := stream.Addr().(*net.TCPAddr).Port
	sockets, err := instance.listenPacketSockets(t.Context(), port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	if len(sockets) != 1 || sockets[0].LocalAddr().(*net.UDPAddr).Port != port {
		t.Fatalf("UDP did not reuse selected TCP port: %v", sockets)
	}
}

func TestConfiguredPacketFactoryLifecycle(t *testing.T) {
	tests := map[string]struct{ scheme string }{
		"UDP":  {"udp"},
		"DTLS": {"dtls"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, m, _ := fixture(t)
			var socket net.PacketConn
			calls := 0
			cfg.ListenerFactories = map[ListenerKey]ListenerFactory{
				{Scheme: tt.scheme, Transport: connection.UDP}: func(ctx context.Context, bound net.PacketConn, _ PacketHandler) (io.Closer, error) {
					if err := m.Do(ctx, func(context.Context) error { return nil }); err != nil {
						return nil, err
					}
					calls++
					socket = bound
					return bound, nil
				},
			}
			instance := makeInstance(t, "reverse:"+tt.scheme+"://example.test:443@127.0.0.1:0", cfg)
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || socket == nil {
				t.Fatalf("factory calls = %d, want 1", calls)
			}
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("idempotent Start called factory %d times", calls)
			}
			if err := m.Do(t.Context(), func(context.Context) error { return instance.Stop() }); err != nil {
				t.Fatal(err)
			}
			if _, err := socket.WriteTo([]byte("closed"), socket.LocalAddr()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("factory socket after Stop = %v", err)
			}
		})
	}
}

func TestConfiguredPacketFactoryFailure(t *testing.T) {
	tests := map[string]struct{ nilCloser bool }{
		"factory error":             {},
		"invalid successful closer": {true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			var socket net.PacketConn
			want := errors.New("protocol listener failed")
			cfg.ListenerFactories = map[ListenerKey]ListenerFactory{
				{Scheme: "udp", Transport: connection.UDP}: func(_ context.Context, bound net.PacketConn, _ PacketHandler) (io.Closer, error) {
					socket = bound
					if tt.nilCloser {
						return nil, nil
					}
					return nil, want
				},
			}
			instance := makeInstance(t, "reverse:udp://example.test:443@127.0.0.1:0", cfg)
			err := instance.Start(t.Context())
			if err == nil || !tt.nilCloser && !errors.Is(err, want) {
				t.Fatalf("Start = %v", err)
			}
			if socket == nil {
				t.Fatal("factory did not receive the bound socket")
			}
			if _, err := socket.WriteTo([]byte("closed"), socket.LocalAddr()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("failed factory socket remains open: %v", err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.LastError() != err {
				t.Fatal("failed factory lifecycle state is inconsistent")
			}
		})
	}
}
