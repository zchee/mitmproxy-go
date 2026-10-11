// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestListenPairIPv6BypassesIPv4Discovery(t *testing.T) {
	lc := new(net.ListenConfig)
	tcp, udp, err := listenPair(t.Context(), "tcp6", "[::1]:0", pairListeners{
		listen:       lc.Listen,
		listenPacket: lc.ListenPacket,
		domain: func(context.Context) (pairDomain, error) {
			t.Fatal("IPv6 invoked IPv4 discovery")
			return pairDomain{}, nil
		},
		retryable: collisionPairBind,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close(); _ = udp.Close() }()
	if tcp.Addr().(*net.TCPAddr).IP.To4() != nil || udp.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		t.Fatal("IPv6 acquisition returned IPv4 sockets")
	}
	if diff := gocmp.Diff(tcp.Addr().String(), udp.LocalAddr().String()); diff != "" {
		t.Fatal(diff)
	}
}

func TestListenPairPartialCancellation(t *testing.T) {
	tests := map[string]struct{ afterUDP bool }{
		"error: cancel after TCP acquisition": {},
		"error: cancel after UDP acquisition": {afterUDP: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ownedTCP, ownedUDP, err := ListenPair(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ownedTCP.Close(); _ = ownedUDP.Close() }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			closes, tcpCalls, udpCalls := 0, 0, 0
			tcp, udp, err := listenPair(ctx, "tcp4", ownedTCP.Addr().String(), pairListeners{
				listen: func(gotCtx context.Context, network, address string) (net.Listener, error) {
					if gotCtx != ctx || network != "tcp4" || address != ownedTCP.Addr().String() {
						t.Fatal("TCP adapter mismatch")
					}
					tcpCalls++
					if !test.afterUDP {
						cancel()
					}
					return &pairedPortListener{Listener: ownedTCP, address: ownedTCP.Addr().(*net.TCPAddr), closes: &closes}, nil
				},
				listenPacket: func(gotCtx context.Context, network, address string) (net.PacketConn, error) {
					if gotCtx != ctx || network != "udp4" || address != ownedUDP.LocalAddr().String() {
						t.Fatal("UDP adapter mismatch")
					}
					udpCalls++
					cancel()
					return ownedUDP, nil
				},
				retryable: collisionPairBind,
			})
			if tcp != nil || udp != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("partial cancellation returned %v %v %v", tcp, udp, err)
			}
			wantUDP := 0
			if test.afterUDP {
				wantUDP = 1
			}
			if diff := gocmp.Diff([]int{1, wantUDP, 1}, []int{tcpCalls, udpCalls, closes}); diff != "" {
				t.Fatalf("acquire/close tallies:\n%s", diff)
			}
			if err := ownedTCP.(*net.TCPListener).SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("partial TCP not closed: %v", err)
			}
			if test.afterUDP {
				if err := ownedUDP.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("partial UDP not closed: %v", err)
				}
			}
		})
	}
}

func TestListenPairOccupiedUDPReleasesTCP(t *testing.T) {
	seedTCP, busy, err := ListenPair(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := seedTCP.Close(); err != nil {
		_ = busy.Close()
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	address := busy.LocalAddr().String()
	lc := new(net.ListenConfig)
	tcp, udp, err := ListenPair(t.Context(), "tcp4", address)
	if tcp != nil || udp != nil || !collisionPairBind(err) {
		t.Fatalf("occupied fixed UDP returned %v %v %v", tcp, udp, err)
	}
	rebound, err := lc.Listen(t.Context(), "tcp4", address)
	if err != nil {
		t.Fatalf("partial TCP was not released: %v", err)
	}
	if err := rebound.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenPairPrecancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	tcp, udp, err := listenPair(ctx, "tcp4", "127.0.0.1:0", pairListeners{})
	if tcp != nil || udp != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled caller returned %v %v %v", tcp, udp, err)
	}
}

func TestListenPairRejectsNonUDPSocket(t *testing.T) {
	tcpCloses, packetCloses := 0, 0
	tcp, udp, err := listenPair(t.Context(), "tcp4", "127.0.0.1:0", pairListeners{
		listen: func(context.Context, string, string) (net.Listener, error) {
			return &portListener{closes: &tcpCloses}, nil
		},
		listenPacket: func(context.Context, string, string) (net.PacketConn, error) {
			return &portPacketConn{closes: &packetCloses}, nil
		},
		retryable: collisionPairBind,
	})
	if tcp != nil || udp != nil || err == nil {
		t.Fatalf("non-UDP primitive returned %v %v %v", tcp, udp, err)
	}
	if diff := gocmp.Diff([]int{1, 1}, []int{tcpCloses, packetCloses}); diff != "" {
		t.Fatalf("partial close tallies:\n%s", diff)
	}
}
