// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestBothListenersSharePort(t *testing.T) {
	cfg, _, _ := fixture(t)
	instance := makeInstance(t, "reverse:https://example.test:443@127.0.0.1:0", cfg)
	streams, packets, err := instance.listenBothSockets(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, stream := range streams {
			_ = stream.Close()
		}
		for _, packet := range packets {
			_ = packet.Close()
		}
	}()
	if len(streams) != 1 || len(packets) != 1 {
		t.Fatalf("stream listeners=%d packet listeners=%d", len(streams), len(packets))
	}
	streamAddr := streams[0].Addr().(*net.TCPAddr)
	packetAddr := packets[0].LocalAddr().(*net.UDPAddr)
	if streamAddr.Port == 0 || streamAddr.Port != packetAddr.Port || !streamAddr.IP.Equal(packetAddr.IP) {
		t.Fatalf("stream address=%v packet address=%v", streamAddr, packetAddr)
	}
}

func TestBothListenersRetryEphemeralCollision(t *testing.T) {
	tests := map[string]struct {
		blockAll  bool
		wantCalls int
	}{
		"first candidate collides": {false, 2},
		"all candidates collide":   {true, sharedPortAttempts},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			instance := makeInstance(t, "reverse:https://example.test:443@127.0.0.1:0", cfg)
			calls := 0
			var blockers []net.PacketConn
			var opened []net.Listener
			t.Cleanup(func() {
				for _, blocker := range blockers {
					_ = blocker.Close()
				}
				for _, listener := range opened {
					_ = listener.Close()
				}
			})
			instance.listenTCP = func(ctx context.Context, network, address string) (net.Listener, error) {
				listener, err := new(net.ListenConfig).Listen(ctx, network, address)
				if err != nil {
					return nil, err
				}
				opened = append(opened, listener)
				calls++
				if tt.blockAll || calls == 1 {
					blocker, err := net.ListenPacket("udp4", listener.Addr().String())
					if err != nil && !isSharedUDPBindRetryable(err) {
						_ = listener.Close()
						return nil, err
					}
					if blocker != nil {
						blockers = append(blockers, blocker)
					}
				}
				return listener, nil
			}
			streams, packets, err := instance.listenBothSockets(t.Context())
			if calls < tt.wantCalls || calls > sharedPortAttempts {
				t.Fatalf("listen calls=%d, expected within [%d,%d]; acquisition error=%v", calls, tt.wantCalls, sharedPortAttempts, err)
			}
			if tt.blockAll {
				if !isSharedUDPBindRetryable(err) || len(streams) != 0 || len(packets) != 0 {
					t.Fatalf("exhausted candidates=%v streams=%v packets=%v", err, streams, packets)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				for _, stream := range streams {
					_ = stream.Close()
				}
				for _, packet := range packets {
					_ = packet.Close()
				}
			}
			for _, stream := range opened {
				if err := stream.Close(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("candidate listener remained open: %v", err)
				}
			}
		})
	}
}
