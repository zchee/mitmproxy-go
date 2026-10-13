// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/netutil/freeport"
)

func TestBothCandidateOwnership(t *testing.T) {
	t.Run("complete wildcard rollback and syscall budget", func(t *testing.T) {
		fatal := errors.New("second family bind refused")
		tests := map[string]struct {
			tcpUnavailable bool
			udpUnavailable bool
			tcpFailure     bool
			udpFailure     bool
			retryUDP       int
			mismatch       bool
			domain         int
			cancel         bool
			wantTCP        int
			wantUDP        int
			wantTCPClose   int
			wantUDPClose   int
			wantStreams    int
			wantPackets    int
			cause          error
		}{
			"complete dual stack":                            {wantTCP: 2, wantUDP: 2, wantStreams: 2, wantPackets: 2},
			"unavailable TCP IPv6":                           {tcpUnavailable: true, wantTCP: 2, wantUDP: 2, wantStreams: 1, wantPackets: 2},
			"unavailable UDP IPv6":                           {udpUnavailable: true, wantTCP: 2, wantUDP: 2, wantStreams: 2, wantPackets: 1},
			"second TCP family fails immediately":            {tcpFailure: true, wantTCP: 2, wantTCPClose: 1, cause: fatal},
			"second UDP family fails immediately":            {udpFailure: true, wantTCP: 2, wantUDP: 2, wantTCPClose: 2, wantUDPClose: 1, cause: fatal},
			"partial UDP set rolls back before retry":        {retryUDP: 1, wantTCP: 4, wantUDP: 4, wantTCPClose: 2, wantUDPClose: 1, wantStreams: 2, wantPackets: 2},
			"different TCP numbers roll back before UDP":     {mismatch: true, wantTCP: 5, wantUDP: 2, wantTCPClose: 2, wantStreams: 2, wantPackets: 2},
			"64 complete acquisition attempts":               {retryUDP: 64, wantTCP: 128, wantUDP: 128, wantTCPClose: 128, wantUDPClose: 64, cause: errors.Unwrap(sharedCollisionCause())},
			"small domain exhausts without another bind":     {retryUDP: 64, domain: 2, wantTCP: 4, wantUDP: 4, wantTCPClose: 4, wantUDPClose: 2, cause: io.EOF},
			"cancellation before activation closes full set": {cancel: true, wantTCP: 2, wantUDP: 2, wantTCPClose: 2, wantUDPClose: 2, cause: context.Canceled},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				cfg, _, _ := fixture(t)
				factoryCalls := 0
				cfg.ListenerFactories = map[ListenerKey]ListenerFactory{
					{Scheme: "dns", Transport: connection.UDP}: func(context.Context, net.PacketConn, PacketHandler) (io.Closer, error) {
						factoryCalls++
						return nil, fatal
					},
				}
				instance := makeInstance(t, "dns@0", cfg)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				selected, tcpCalls, udpCalls, tcpClosed, udpClosed := 0, 0, 0, 0, 0
				instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
					return candidateCursor(func(context.Context) (int, error) {
						if test.domain != 0 && selected == test.domain {
							return 0, io.EOF
						}
						selected++
						if tcpClosed != 2*(selected-1) && !test.tcpUnavailable && !test.tcpFailure {
							t.Fatalf("candidate %d selected before full TCP rollback: closes=%d", selected, tcpClosed)
						}
						if selected > 1 && test.retryUDP != 0 && udpClosed != selected-1 {
							t.Fatalf("candidate %d selected before partial UDP rollback: closes=%d", selected, udpClosed)
						}
						return 50000 + selected, nil
					}), nil
				}
				fallback := false
				instance.listenTCP = func(_ context.Context, network, address string) (net.Listener, error) {
					tcpCalls++
					_, number, err := net.SplitHostPort(address)
					if err != nil {
						t.Fatal(err)
					}
					port, err := strconv.Atoi(number)
					if err != nil {
						t.Fatal(err)
					}
					if network == "tcp6" {
						if test.tcpUnavailable {
							return nil, syscall.EAFNOSUPPORT
						}
						if test.tcpFailure {
							return nil, fatal
						}
						if test.mismatch && selected == 1 {
							if !fallback {
								fallback = true
								return nil, sharedCollisionCause()
							}
							if port != 0 {
								t.Fatal("originally-zero IPv6 fallback lost native :0")
							}
							port = 50200
						}
					}
					return &candidateTestTCP{address: &net.TCPAddr{Port: port}, closes: &tcpClosed}, nil
				}
				instance.listenUDP = func(_ context.Context, network, address string) (net.PacketConn, error) {
					udpCalls++
					addr, err := net.ResolveUDPAddr(network, address)
					if err != nil {
						t.Fatal(err)
					}
					if addr.Port != 50000+selected {
						t.Fatalf("UDP preceded shared TCP set: %v", addr)
					}
					if network == "udp6" {
						if test.udpUnavailable {
							return nil, syscall.EAFNOSUPPORT
						}
						if test.udpFailure {
							return nil, fatal
						}
						if selected <= test.retryUDP {
							return nil, sharedCollisionCause()
						}
						if test.cancel {
							cancel()
						}
					}
					return &candidateTestUDP{address: addr, closes: &udpClosed}, nil
				}
				var streams []net.Listener
				var packets []net.PacketConn
				var err error
				if test.cause != nil {
					err = instance.Start(ctx)
					if !errors.Is(err, test.cause) || factoryCalls != 0 || instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.port != 0 || !strings.Contains(err.Error(), "*:0") {
						t.Fatalf("failed acquisition activated/published/lost cause or request: factories=%d err=%v", factoryCalls, err)
					}
					if test.domain != 0 && !errors.Is(err, errors.Unwrap(sharedCollisionCause())) {
						t.Fatalf("domain exhaustion lost original UDP cause: %v", err)
					}
					if test.retryUDP == 64 && test.domain == 0 && !strings.Contains(err.Error(), "candidates=64 TCP_binds=128 UDP_binds=128") {
						t.Fatalf("exhaustion lacks actual family-specific tallies: %v", err)
					}
				} else {
					streams, packets, err = instance.listenBothSockets(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}
				if diff := gocmp.Diff([]int{test.wantTCP, test.wantUDP, test.wantTCPClose, test.wantUDPClose, test.wantStreams, test.wantPackets}, []int{tcpCalls, udpCalls, tcpClosed, udpClosed, len(streams), len(packets)}); diff != "" {
					t.Fatalf("syscalls/rollback/live sets (-want +got):\n%s", diff)
				}
				for _, stream := range streams {
					_ = stream.Close()
				}
				for _, packet := range packets {
					_ = packet.Close()
				}
				t.Logf("candidates=%d TCP_binds=%d UDP_binds=%d", selected, tcpCalls, udpCalls)
			})
		}
	})
	t.Run("real sockets reusable Start and exactly-once Stop", func(t *testing.T) {
		tests := map[string]struct {
			spec, scheme string
			cancel       bool
			cancelFirst  bool
		}{
			"standalone DNS": {spec: "dns@127.0.0.1:0", scheme: "dns"},
			"reverse DNS":    {spec: "reverse:dns://example.test@127.0.0.1:0", scheme: "dns"},
			"reverse HTTPS":  {spec: "reverse:https://example.test@127.0.0.1:0", scheme: "https"},
			"cancellation and Stop serialize closure":      {spec: "dns@127.0.0.1:0", scheme: "dns", cancel: true},
			"cancelled acquisition permits reusable Start": {spec: "dns@127.0.0.1:0", scheme: "dns", cancelFirst: true},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				cfg, _, _ := fixture(t)
				instance := makeInstance(t, test.spec, cfg)
				factory, err := instance.packetFactory()
				if err != nil {
					t.Fatal(err)
				}
				failure := errors.New("factory refused complete socket set")
				if test.cancelFirst {
					failure = context.Canceled
				}
				firstCtx, cancelFirst := context.WithCancel(t.Context())
				defer cancelFirst()
				factoryCalls := 0
				instance.factories[ListenerKey{Scheme: test.scheme, Transport: connection.UDP}] = func(ctx context.Context, socket net.PacketConn, handler PacketHandler) (io.Closer, error) {
					factoryCalls++
					if factoryCalls == 1 && !test.cancelFirst {
						return nil, failure
					}
					return factory(ctx, socket, handler)
				}
				var streams []*candidateOwnedTCP
				var packets []*candidateOwnedUDP
				for range 2 {
					tcp, udp, err := freeport.ListenPair(t.Context(), "tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
					streams = append(streams, &candidateOwnedTCP{Listener: tcp})
					packets = append(packets, &candidateOwnedUDP{PacketConn: udp})
				}
				nextStart, current := 0, 0
				instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
					current = nextStart
					nextStart++
					return candidateCursor(func(context.Context) (int, error) { return streams[current].Addr().(*net.TCPAddr).Port, nil }), nil
				}
				instance.listenTCP = func(_ context.Context, network, address string) (net.Listener, error) {
					if network != "tcp" || address != streams[current].Addr().String() {
						t.Fatalf("TCP selection identity: %s %s", network, address)
					}
					return streams[current], nil
				}
				instance.listenUDP = func(_ context.Context, network, address string) (net.PacketConn, error) {
					if network != "udp" || address != packets[current].LocalAddr().String() {
						t.Fatalf("UDP selection identity: %s %s", network, address)
					}
					if current == 0 && test.cancelFirst {
						cancelFirst()
					}
					return packets[current], nil
				}
				if err := instance.Start(firstCtx); !errors.Is(err, failure) || instance.IsRunning() || instance.port != 0 {
					t.Fatalf("factory failure published state or changed request: %v", err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if err := instance.Start(ctx); err != nil {
					t.Fatal(err)
				}
				if !instance.IsRunning() || len(instance.ListenAddrs()) != 2 || !gocmp.Equal(instance.ListenAddrs()[0], instance.ListenAddrs()[1]) || instance.LastError() != nil {
					t.Fatalf("reused Start failed to publish complete shared set: %v", instance.ListenAddrs())
				}
				if test.cancel {
					cancel()
				}
				if err := instance.Stop(); err != nil {
					t.Fatal(err)
				}
				if err := instance.Stop(); err != nil {
					t.Fatal(err)
				}
				for index := range streams {
					if streams[index].closes.Load() != 1 || packets[index].closes.Load() != 1 {
						t.Fatalf("owned set %d close counts TCP=%d UDP=%d", index, streams[index].closes.Load(), packets[index].closes.Load())
					}
				}
				wantFactories := 2
				if test.cancelFirst {
					wantFactories = 1
				}
				if nextStart != 2 || factoryCalls != wantFactories || instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
					t.Fatalf("reusable lifecycle retained state: discoveries=%d factories=%d", nextStart, factoryCalls)
				}
			})
		}
	})
}

type candidateOwnedTCP struct {
	net.Listener
	closes atomic.Int32
}

func (socket *candidateOwnedTCP) Close() error { socket.closes.Add(1); return socket.Listener.Close() }

type candidateOwnedUDP struct {
	net.PacketConn
	closes atomic.Int32
}

func (socket *candidateOwnedUDP) Close() error {
	socket.closes.Add(1)
	return socket.PacketConn.Close()
}
