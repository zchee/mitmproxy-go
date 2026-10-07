// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

type sharedUDPBindCase struct {
	failure   error
	failures  int
	fixed     bool
	wantCalls int
}

func checkSharedUDPBind(t *testing.T, tt sharedUDPBindCase) {
	t.Helper()
	cfg, _, _ := fixture(t)
	instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
	var streams []net.Listener
	var sockets []net.PacketConn
	t.Cleanup(func() {
		for _, stream := range streams {
			_ = stream.Close()
		}
		for _, socket := range sockets {
			_ = socket.Close()
		}
	})
	if tt.fixed {
		probe, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		instance.port = probe.Addr().(*net.TCPAddr).Port
		if err := probe.Close(); err != nil {
			t.Fatal(err)
		}
	}
	instance.listenTCP = func(ctx context.Context, network, address string) (net.Listener, error) {
		stream, err := new(net.ListenConfig).Listen(ctx, network, address)
		if err == nil {
			streams = append(streams, stream)
		}
		return stream, err
	}
	calls := 0
	instance.listenUDP = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		calls++
		if calls <= tt.failures {
			return nil, fmt.Errorf("UDP candidate acquisition: %w", tt.failure)
		}
		socket, err := new(net.ListenConfig).ListenPacket(ctx, network, address)
		if err == nil {
			sockets = append(sockets, socket)
		}
		return socket, err
	}
	accepted, packets, err := instance.listenBothSockets(t.Context())
	if calls != tt.wantCalls {
		t.Fatalf("UDP candidate calls = %d, want %d; error=%v", calls, tt.wantCalls, err)
	}
	if tt.failures >= tt.wantCalls {
		if !errors.Is(err, tt.failure) || len(accepted) != 0 || len(packets) != 0 {
			t.Fatalf("terminal acquisition = %v, TCP=%d UDP=%d", err, len(accepted), len(packets))
		}
	} else {
		if err != nil || len(accepted) != 1 || len(packets) != 1 {
			t.Fatalf("successful acquisition = %v, TCP=%d UDP=%d", err, len(accepted), len(packets))
		}
		if accepted[0].Addr().(*net.TCPAddr).Port != packets[0].LocalAddr().(*net.UDPAddr).Port {
			t.Fatal("successful transports do not share a port")
		}
		_ = accepted[0].Close()
		_ = packets[0].Close()
	}
	for _, stream := range streams {
		if err := stream.Close(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("candidate TCP listener remained open: %v", err)
		}
	}
}

func TestSharedUDPBindFaults(t *testing.T) {
	failure := errors.New("UDP acquisition denied")
	tests := map[string]struct {
		failure   error
		failures  int
		fixed     bool
		wantCalls int
	}{
		"same port success":                 {failure: failure, wantCalls: 1},
		"other UDP errors fail immediately": {failure: failure, failures: 1, wantCalls: 1},
		"fixed port fails immediately":      {failure: failure, failures: 1, fixed: true, wantCalls: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) { checkSharedUDPBind(t, tt) })
	}
}
