// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestPairForbiddenIntervalAdapters(t *testing.T) {
	tests := map[string]struct{ tcpExcluded, udpExcluded bool }{
		"success: TCP-only exclusion":     {tcpExcluded: true},
		"success: UDP-only exclusion":     {udpExcluded: true},
		"success: overlapping exclusions": {tcpExcluded: true, udpExcluded: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ownedTCP, ownedUDP, err := ListenPair(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ownedTCP.Close(); _ = ownedUDP.Close() }()
			port := ownedTCP.Addr().(*net.TCPAddr).Port
			blocked := portRange{port - 100, port - 1}
			var exclusions []portRange
			if test.tcpExcluded {
				exclusions = append(exclusions, blocked)
			}
			if test.udpExcluded {
				exclusions = append(exclusions, blocked)
			}
			closes, tcpCalls, udpCalls := 0, 0, 0
			listenTCP := func(ctx context.Context, network, address string) (net.Listener, error) {
				if ctx != t.Context() || network != "tcp4" {
					t.Fatalf("invalid bind context/family %s", network)
				}
				_, number, err := net.SplitHostPort(address)
				if err != nil {
					t.Fatal(err)
				}
				requested, err := strconv.Atoi(number)
				if err != nil {
					t.Fatal(err)
				}
				tcpCalls++
				if requested == 0 {
					return &pairedPortListener{address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: blocked.first + tcpCalls - 1}, closes: &closes}, nil
				}
				if requested != port {
					t.Fatalf("explicit candidate %d, want complement %d", requested, port)
				}
				return ownedTCP, nil
			}
			listenUDP := func(ctx context.Context, network, address string) (*net.UDPConn, error) {
				if ctx != t.Context() || network != "udp4" {
					t.Fatalf("invalid UDP bind context/family %s", network)
				}
				udpCalls++
				_, number, err := net.SplitHostPort(address)
				if err != nil {
					t.Fatal(err)
				}
				requested, err := strconv.Atoi(number)
				if err != nil {
					t.Fatal(err)
				}
				if inPortRanges(requested, exclusions) {
					return nil, fmt.Errorf("excluded-range bind: %w", syscall.Errno(10013))
				}
				if requested != port {
					t.Fatalf("UDP candidate %d, want %d", requested, port)
				}
				return ownedUDP, nil
			}
			parentTCP, parentUDP, parentErr := parentPairAdapter(func() (net.Listener, error) { return listenTCP(t.Context(), "tcp4", "127.0.0.1:0") }, func(address *net.UDPAddr) (*net.UDPConn, error) {
				return listenUDP(t.Context(), "udp4", address.String())
			}, windowsPairBindFixture)
			if parentTCP != nil || parentUDP != nil || !errors.Is(parentErr, syscall.Errno(10013)) {
				t.Fatalf("parent did not preserve exclusion exhaustion: %v %v %v", parentTCP, parentUDP, parentErr)
			}
			if diff := gocmp.Diff([]int{64, 64, 64}, []int{tcpCalls, udpCalls, closes}); diff != "" {
				t.Fatalf("parent bind/close tallies:\n%s", diff)
			}
			tcpCalls, udpCalls, closes = 0, 0, 0
			tcp, udp, err := listenPair(t.Context(), "tcp4", "127.0.0.1:0", pairListeners{
				listen: listenTCP,
				listenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
					return listenUDP(ctx, network, address)
				},
				domain: func(context.Context) (pairDomain, error) {
					return pairDomain{available: true, bounds: portRange{blocked.first, port}, excluded: exclusions}, nil
				},
				retryable: windowsPairBindFixture,
			})
			if err != nil || tcp != ownedTCP || udp != ownedUDP {
				t.Fatalf("candidate did not return live complement: %v %v %v", tcp, udp, err)
			}
			if diff := gocmp.Diff([]int{1, 1, 0}, []int{tcpCalls, udpCalls, closes}); diff != "" {
				t.Fatalf("candidate bind/close tallies:\n%s", diff)
			}
			t.Logf("parent exhausted TCP=64 UDP=64 closed=64; candidate TCP=1 UDP=1 closed=0; interval=%d..%d complement=%d", blocked.first, blocked.last, port)
		})
	}
}

func TestListenPairStaleKnowledge(t *testing.T) {
	lc := new(net.ListenConfig)
	closes, udpCalls, tcpCalls := 0, 0, 0
	var rejected net.Listener
	tcp, udp, err := listenPair(t.Context(), "tcp4", "127.0.0.1:0", pairListeners{
		domain: func(context.Context) (pairDomain, error) {
			return pairDomain{available: true, bounds: portRange{49152, 65535}}, nil
		},
		retryable: windowsPairBindFixture,
		listen: func(ctx context.Context, network, address string) (net.Listener, error) {
			if rejected != nil && closes != 1 {
				t.Fatal("stale retry preceded partial rollback")
			}
			tcpCalls++
			listener, err := lc.Listen(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if rejected == nil {
				rejected = listener
				return &pairedPortListener{Listener: listener, address: listener.Addr().(*net.TCPAddr), closes: &closes}, nil
			}
			return listener, nil
		},
		listenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			udpCalls++
			if udpCalls == 1 {
				return nil, fmt.Errorf("stale exclusion: %w", &net.OpError{Op: "listen", Net: network, Err: syscall.Errno(10013)})
			}
			return lc.ListenPacket(ctx, network, address)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close(); _ = udp.Close() }()
	if closes != 1 || tcpCalls < 2 || tcpCalls > 64 || udpCalls < 2 || udpCalls > 64 {
		t.Fatalf("stale bind tallies TCP=%d UDP=%d closes=%d", tcpCalls, udpCalls, closes)
	}
	if err := rejected.(*net.TCPListener).SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("rejected socket still live: %v", err)
	}
	if tcp.Addr().String() != udp.LocalAddr().String() {
		t.Fatal("stale retry returned mismatched pair")
	}
}
