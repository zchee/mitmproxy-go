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
	failure       error
	failures      int
	fixed         bool
	realCollision bool
	wantCalls     int
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
	calls, realRejections := 0, 0
	collided := false
	instance.listenUDP = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		calls++
		if calls <= tt.failures {
			return nil, fmt.Errorf("UDP candidate acquisition: %w", tt.failure)
		}
		if tt.realCollision && !collided {
			blocker, err := new(net.ListenConfig).ListenPacket(ctx, network, address)
			if err != nil {
				if !tt.fixed && isSharedUDPBindRetryable(err) {
					realRejections++
				} else {
					t.Errorf("reserving real UDP collision: %v", err)
				}
				return nil, err
			}
			sockets = append(sockets, blocker)
			defer func() { _ = blocker.Close() }()
			collided = true
		}
		socket, err := new(net.ListenConfig).ListenPacket(ctx, network, address)
		if err == nil {
			sockets = append(sockets, socket)
		} else if !tt.fixed && isSharedUDPBindRetryable(err) {
			realRejections++
		} else {
			t.Errorf("non-retryable real UDP bind: %v", err)
		}
		return socket, err
	}
	accepted, packets, err := instance.listenBothSockets(t.Context())
	wantCalls := tt.wantCalls + realRejections
	if calls != wantCalls || calls > sharedPortAttempts {
		t.Fatalf("UDP candidate calls = %d, want %d (real rejections=%d, budget=%d); error=%v", calls, wantCalls, realRejections, sharedPortAttempts, err)
	}
	if tt.realCollision && (!collided || realRejections == 0) {
		t.Fatal("real UDP collision did not reject a candidate")
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
		failure       error
		failures      int
		fixed         bool
		realCollision bool
		wantCalls     int
	}{
		"same port success":                 {failure: failure, wantCalls: 1},
		"real UDP collision is counted":     {failure: failure, realCollision: true, wantCalls: 1},
		"other UDP errors fail immediately": {failure: failure, failures: 1, wantCalls: 1},
		"fixed port fails immediately":      {failure: failure, failures: 1, fixed: true, wantCalls: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) { checkSharedUDPBind(t, tt) })
	}
}
