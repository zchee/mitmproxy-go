// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

type candidateCursor func(context.Context) (int, error)

func (next candidateCursor) Next(ctx context.Context) (int, error) { return next(ctx) }

func TestBothCandidateSelection(t *testing.T) {
	t.Run("fixture and product allocators are exclusive", func(t *testing.T) {
		tests := map[string]struct{ selects bool }{
			"fixture preserves original request": {},
			"product requests candidate number":  {selects: true},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				cfg, _, _ := fixture(t)
				instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
				instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
					t.Fatal("fixture retained product allocator")
					return nil, nil
				}
				pair := prepareDNSSockets(t, instance)
				if instance.portCandidates != nil {
					t.Fatal("pre-acquired fixture did not disable product selection")
				}
				tcp, udp := pair.tcp, pair.udp
				selections, draws := 0, 0
				wantRequest := "127.0.0.1:0"
				if test.selects {
					wantRequest = pair.address
					pair.tcpRequest = wantRequest
					instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
						selections++
						return candidateCursor(func(context.Context) (int, error) {
							draws++
							return tcp.Addr().(*net.TCPAddr).Port, nil
						}), nil
					}
				}
				var requests []string
				instance.listenTCP = func(ctx context.Context, network, address string) (net.Listener, error) {
					requests = append(requests, address)
					return pair.listenTCP(ctx, network, address)
				}
				if err := pair.start(t.Context(), instance); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff([]string{wantRequest}, requests); diff != "" {
					t.Fatalf("TCP allocator request (-want +got):\n%s", diff)
				}
				wantSelections := 0
				if test.selects {
					wantSelections = 1
				}
				if diff := gocmp.Diff([]int{wantSelections, wantSelections, 0}, []int{selections, draws, instance.port}); diff != "" {
					t.Fatalf("allocator calls and requested port (-want +got):\n%s", diff)
				}
				if err := instance.Stop(); err != nil {
					t.Fatal(err)
				}
				assertDNSSocketsClosed(t, tcp, udp)
			})
		}
	})
	t.Run("host and requested port preservation", func(t *testing.T) {
		tests := map[string]struct {
			host    string
			port    int
			selects bool
		}{
			"IPv4 literal":             {host: "127.0.0.1", selects: true},
			"IPv4 mapped literal":      {host: "::ffff:127.0.0.1", selects: true},
			"empty wildcard":           {selects: true},
			"IPv6 literal":             {host: "::1"},
			"IPv6 zone identity":       {host: "fe80::1%test-zone"},
			"IPv4-only hostname":       {host: "ipv4-only.example.test"},
			"mixed-family hostname":    {host: "mixed.example.test"},
			"numeric-looking hostname": {host: "127.0.0.1.example.test"},
			"localhost hostname":       {host: "localhost"},
			"fixed IPv4":               {host: "127.0.0.1", port: 50321},
			"fixed wildcard":           {port: 50321},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				cfg, _, _ := fixture(t)
				instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
				instance.host, instance.port = test.host, test.port
				selected, tcpCalls, udpCalls := 0, 0, 0
				instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
					selected++
					return candidateCursor(func(context.Context) (int, error) { return 50123, nil }), nil
				}
				cause := fmt.Errorf("TCP bind: %w", syscall.Errno(10013))
				instance.listenTCP = func(_ context.Context, network, address string) (net.Listener, error) {
					tcpCalls++
					wantNetwork, wantHost, wantPort := "tcp", test.host, test.port
					if test.host == "" {
						wantNetwork, wantHost = "tcp4", "0.0.0.0"
					}
					if test.selects {
						wantPort = 50123
					}
					if diff := gocmp.Diff([]string{wantNetwork, net.JoinHostPort(wantHost, strconv.Itoa(wantPort))}, []string{network, address}); diff != "" {
						t.Fatalf("native host/network and candidate (-want +got):\n%s", diff)
					}
					return nil, cause
				}
				instance.listenUDP = func(context.Context, string, string) (net.PacketConn, error) {
					udpCalls++
					return nil, cause
				}
				streams, packets, err := instance.listenBothSockets(t.Context())
				wantSelection := 0
				if test.selects {
					wantSelection = 1
				}
				if diff := gocmp.Diff([]int{wantSelection, 1, 0, test.port}, []int{selected, tcpCalls, udpCalls, instance.port}); diff != "" {
					t.Fatalf("selection/bind/request tallies (-want +got):\n%s", diff)
				}
				if len(streams) != 0 || len(packets) != 0 || !errors.Is(err, syscall.Errno(10013)) {
					t.Fatalf("TCP fail-fast lost cause or acquired sockets: %v", err)
				}
			})
		}
	})
	t.Run("platform default", func(t *testing.T) {
		cfg, _, _ := fixture(t)
		instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
		if (instance.portCandidates != nil) != (runtime.GOOS == "windows") {
			t.Fatalf("candidate wiring on %s is incorrect", runtime.GOOS)
		}
	})
	t.Run("selection failures acquire nothing", func(t *testing.T) {
		cause := errors.New("candidate discovery or sampling unavailable")
		tests := map[string]struct {
			discovery bool
			cancelled bool
		}{
			"discovery failure": {discovery: true},
			"sampling failure":  {},
			"precancelled":      {cancelled: true},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				cfg, _, _ := fixture(t)
				instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if test.cancelled {
					cancel()
				}
				instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
					if test.cancelled {
						t.Fatal("precancelled Start entered discovery")
					}
					if test.discovery {
						return nil, &net.OpError{Op: "select", Net: "tcp4/udp4", Err: cause}
					}
					return candidateCursor(func(context.Context) (int, error) { return 0, cause }), nil
				}
				instance.listenTCP = func(context.Context, string, string) (net.Listener, error) {
					t.Fatal("failed selection acquired TCP")
					return nil, nil
				}
				instance.listenUDP = func(context.Context, string, string) (net.PacketConn, error) {
					t.Fatal("failed selection acquired UDP")
					return nil, nil
				}
				err := instance.Start(ctx)
				want := cause
				if test.cancelled {
					want = context.Canceled
				}
				if !errors.Is(err, want) || instance.IsRunning() || len(instance.ListenAddrs()) != 0 || instance.port != 0 || !strings.Contains(err.Error(), "127.0.0.1:0") {
					t.Fatalf("failed Start state/diagnostic/cause: %v", err)
				}
			})
		}
	})
	t.Run("parent allocator versus candidate complement", func(t *testing.T) {
		// The old production callback receives :0 and selects adjacent denied
		// ports. The candidate seam supplies the same domain's usable complement;
		// freeport separately certifies its exclusion filtering and sampler.
		tests := map[string]struct {
			parent   bool
			tcpCause error
		}{
			"old allocator exhausts denied interval":    {parent: true},
			"candidate complement reaches complete set": {},
			"old allocator TCP access denial":           {parent: true, tcpCause: syscall.Errno(10013)},
			"old allocator TCP collision":               {parent: true, tcpCause: syscall.Errno(10048)},
			"candidate TCP access denial":               {tcpCause: syscall.Errno(10013)},
			"candidate TCP collision":                   {tcpCause: syscall.Errno(10048)},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				cfg, _, _ := fixture(t)
				instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
				instance.portCandidates = nil
				const first, last = 50000, 50100
				if !test.parent {
					instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
						return candidateCursor(func(context.Context) (int, error) { return last + 1, nil }), nil
					}
				}
				cause := fmt.Errorf("TCP bind: %w", test.tcpCause)
				tcpCalls, udpCalls, closes := 0, 0, 0
				instance.listenTCP = func(_ context.Context, _, address string) (net.Listener, error) {
					tcpCalls++
					if test.tcpCause != nil {
						return nil, cause
					}
					_, number, err := net.SplitHostPort(address)
					if err != nil {
						t.Fatal(err)
					}
					port, err := strconv.Atoi(number)
					if err != nil {
						t.Fatal(err)
					}
					if test.parent {
						if port != 0 {
							t.Fatal("parent allocator no longer receives native :0")
						}
						port = first + tcpCalls - 1
					}
					if closes != tcpCalls-1 {
						t.Fatal("retry started before complete rollback")
					}
					return &candidateTestTCP{address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, closes: &closes}, nil
				}
				instance.listenUDP = func(_ context.Context, _, address string) (net.PacketConn, error) {
					udpCalls++
					addr, err := net.ResolveUDPAddr("udp", address)
					if err != nil {
						t.Fatal(err)
					}
					if addr.Port >= first && addr.Port <= last {
						return nil, sharedCollisionCause()
					}
					return &candidateTestUDP{address: addr}, nil
				}
				streams, packets, err := instance.listenBothSockets(t.Context())
				wantTCP, wantUDP, wantCloses := 1, 1, 0
				if test.tcpCause != nil {
					wantUDP = 0
					if !errors.Is(err, cause) {
						t.Fatalf("TCP fail-fast cause: %v", err)
					}
				} else if test.parent {
					wantTCP, wantUDP, wantCloses = sharedPortAttempts, sharedPortAttempts, sharedPortAttempts
					if !isSharedUDPBindRetryable(err) || len(streams) != 0 || len(packets) != 0 {
						t.Fatalf("old allocator did not exhaust: %v", err)
					}
				} else if err != nil || len(streams) != 1 || len(packets) != 1 {
					t.Fatalf("usable complement did not complete Both: %v", err)
				}
				if diff := gocmp.Diff([]int{wantTCP, wantUDP, wantCloses}, []int{tcpCalls, udpCalls, closes}); diff != "" {
					t.Fatalf("actual per-protocol bind/rollback tallies (-want +got):\n%s", diff)
				}
				for _, stream := range streams {
					_ = stream.Close()
				}
				for _, packet := range packets {
					_ = packet.Close()
				}
				t.Logf("TCP_binds=%d UDP_binds=%d", tcpCalls, udpCalls)
			})
		}
	})
}

func sharedCollisionCause() error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("UDP bind: %w", syscall.Errno(10048))
	}
	return fmt.Errorf("UDP bind: %w", syscall.EADDRINUSE)
}

type candidateTestTCP struct {
	net.Listener
	address *net.TCPAddr
	closes  *int
}

func (socket *candidateTestTCP) Addr() net.Addr { return socket.address }
func (socket *candidateTestTCP) Close() error {
	if socket.closes != nil {
		*socket.closes++
	}
	if socket.Listener != nil {
		return socket.Listener.Close()
	}
	return nil
}

type candidateTestUDP struct {
	net.PacketConn
	address *net.UDPAddr
	closes  *int
}

func (socket *candidateTestUDP) LocalAddr() net.Addr { return socket.address }
func (socket *candidateTestUDP) Close() error {
	if socket.closes != nil {
		*socket.closes++
	}
	if socket.PacketConn != nil {
		return socket.PacketConn.Close()
	}
	return nil
}
