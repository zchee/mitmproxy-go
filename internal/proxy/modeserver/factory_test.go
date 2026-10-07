// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

func TestListenerFactoryValidation(t *testing.T) {
	cfg, _, _ := fixture(t)
	mode, err := modespec.Parse("reverse:quic://example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	factory := func(context.Context, net.PacketConn, PacketHandler) (io.Closer, error) {
		return nil, errors.New("unused")
	}
	tests := map[string]struct {
		key     ListenerKey
		factory ListenerFactory
	}{
		"nil factory":  {ListenerKey{"quic", connection.UDP}, nil},
		"TCP key":      {ListenerKey{"quic", connection.TCP}, factory},
		"empty scheme": {ListenerKey{"", connection.UDP}, factory},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg.ListenerFactories = map[ListenerKey]ListenerFactory{tt.key: tt.factory}
			if _, err := New(mode, cfg); err == nil {
				t.Fatal("accepted invalid factory")
			}
		})
	}
}

func TestListenerFactoryClonedAndOwnership(t *testing.T) {
	cfg, m, _ := fixture(t)
	key := ListenerKey{"udp", connection.UDP}
	var socket net.PacketConn
	called := 0
	cfg.ListenerFactories = map[ListenerKey]ListenerFactory{
		key: func(ctx context.Context, conn net.PacketConn, _ PacketHandler) (io.Closer, error) {
			// Dispatch is available during factory execution; no hook frame is held.
			if err := m.Do(ctx, func(context.Context) error { return nil }); err != nil {
				return nil, err
			}
			called++
			socket = conn
			return conn, nil
		},
	}
	instance := makeInstance(t, "reverse:udp://example.test:443@127.0.0.1:0", cfg)
	delete(cfg.ListenerFactories, key)
	factory, err := instance.packetFactory()
	if err != nil {
		t.Fatal(err)
	}
	bound, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := factory(t.Context(), bound, func(context.Context, layer.PacketTransport) error { return nil })
	if err != nil {
		_ = bound.Close()
		t.Fatal(err)
	}
	if called != 1 || socket != bound {
		t.Fatal("factory override was not copied")
	}
	if err := m.Do(t.Context(), func(context.Context) error { return listener.Close() }); err != nil {
		t.Fatal(err)
	}
	if _, err := socket.WriteTo([]byte("closed"), socket.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("socket after Stop = %v", err)
	}
}

func TestListenerFactoryFailureLeavesCallerOwnership(t *testing.T) {
	cfg, _, _ := fixture(t)
	want := errors.New("factory failed")
	cfg.ListenerFactories = map[ListenerKey]ListenerFactory{
		{Scheme: "quic", Transport: connection.UDP}: func(context.Context, net.PacketConn, PacketHandler) (io.Closer, error) {
			return nil, want
		},
	}
	instance := makeInstance(t, "reverse:quic://example.test:443@127.0.0.1:0", cfg)
	factory, err := instance.packetFactory()
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = socket.Close() }()
	listener, err := factory(t.Context(), socket, func(context.Context, layer.PacketTransport) error { return nil })
	if listener != nil || !errors.Is(err, want) {
		t.Fatalf("factory = %v, %v", listener, err)
	}
	if _, err := socket.WriteTo([]byte("still owned"), socket.LocalAddr()); err != nil {
		t.Fatalf("factory took failed socket ownership: %v", err)
	}
}

type observedPacketSocket struct {
	net.PacketConn
	closed   chan struct{}
	ready    chan struct{}
	received chan error
	once     sync.Once
	readOnce sync.Once
}

func observeFactoryPacketSocket(t *testing.T, socket net.PacketConn) *observedPacketSocket {
	t.Helper()
	if err := packettransport.ConfigureSocketBuffers(socket.(*net.UDPConn)); err != nil {
		_ = socket.Close()
		t.Fatal(err)
	}
	return &observedPacketSocket{PacketConn: socket, closed: make(chan struct{}), ready: make(chan struct{}), received: make(chan error, 2)}
}

func (s *observedPacketSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	s.readOnce.Do(func() { close(s.ready) })
	n, addr, err := s.PacketConn.ReadFrom(p)
	s.received <- err
	return n, addr, err
}

func (s *observedPacketSocket) Close() error {
	err := s.PacketConn.Close()
	s.once.Do(func() { close(s.closed) })
	return err
}

func TestPacketFactoryCloseEvictsWithoutJoining(t *testing.T) {
	tests := map[string]struct{ cancelContext bool }{
		"close":                {},
		"context cancellation": {true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, m, _ := fixture(t)
			instance := makeInstance(t, "reverse:udp://example.test:443@127.0.0.1:0", cfg)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			accepted := make(chan layer.PacketTransport, 1)
			release := make(chan struct{})
			done := make(chan struct{})
			observed := observeFactoryPacketSocket(t, socket)
			listener, err := instance.servePackets(ctx, observed, func(_ context.Context, conn layer.PacketTransport) error {
				defer close(done)
				accepted <- conn
				<-release
				return conn.Close()
			})
			if err != nil {
				_ = socket.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() { close(release); _ = listener.Close(); await(t, done) })
			await(t, observed.ready)
			peer, err := net.Dial("udp4", socket.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			if _, err := peer.Write([]byte("datagram")); err != nil {
				t.Fatal(err)
			}
			if err := await(t, observed.received); err != nil {
				t.Fatalf("factory datagram socket delivery: %v", err)
			}
			conn := await(t, accepted)
			if tt.cancelContext {
				cancel()
			} else if err := m.Do(t.Context(), func(context.Context) error { return listener.Close() }); err != nil {
				t.Fatal(err)
			}
			await(t, conn.Context().Done())
			await(t, observed.closed)
			select {
			case <-done:
				t.Fatal("factory unexpectedly completed its blocked handler")
			default:
			}
			if _, err := socket.WriteTo([]byte("closed"), socket.LocalAddr()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed socket write = %v", err)
			}
		})
	}
}

func TestPacketFactoryHandlerOutsideDispatch(t *testing.T) {
	cfg, m, _ := fixture(t)
	instance := makeInstance(t, "reverse:udp://example.test:443@127.0.0.1:0", cfg)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	observed := observeFactoryPacketSocket(t, socket)
	listener, err := instance.servePackets(t.Context(), observed, func(ctx context.Context, conn layer.PacketTransport) error {
		defer func() { _ = conn.Close() }()
		err := m.Do(ctx, func(context.Context) error { return nil })
		result <- err
		return err
	})
	if err != nil {
		_ = socket.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	await(t, observed.ready)
	peer, err := net.Dial("udp4", socket.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
	if err := await(t, observed.received); err != nil {
		t.Fatalf("factory datagram socket delivery: %v", err)
	}
	if err := await(t, result); err != nil {
		t.Fatal(err)
	}
}
