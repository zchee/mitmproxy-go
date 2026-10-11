// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestListenPairLiveOwnership(t *testing.T) {
	tests := map[string]struct {
		network string
		address string
	}{
		"success: IPv4 identity": {network: "tcp4", address: "127.0.0.1:0"},
		"success: IPv6 identity": {network: "tcp6", address: "[::1]:0"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tcp, udp, err := ListenPair(ctx, test.network, test.address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
			if diff := gocmp.Diff(tcp.Addr().String(), udp.LocalAddr().String()); diff != "" {
				t.Fatalf("paired identity (-TCP +UDP):\n%s", diff)
			}
			cancel()
			client, err := net.DialTimeout(test.network, tcp.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("returned TCP listener is not live: %v", err)
			}
			defer func() { _ = client.Close() }()
			accepted, err := tcp.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = accepted.Close() }()
			peer, err := net.DialTimeout("udp"+test.network[3:], udp.LocalAddr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			if err := udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write([]byte("owned pair")); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 64)
			n, _, err := udp.ReadFromUDP(buffer)
			if err != nil {
				t.Fatalf("returned UDP socket is not live: %v", err)
			}
			if diff := gocmp.Diff("owned pair", string(buffer[:n])); diff != "" {
				t.Fatalf("UDP payload (-want +got):\n%s", diff)
			}
		})
	}
}

func TestListenPairSelection(t *testing.T) {
	collision := fmt.Errorf("wrapped bind: %w", syscall.EADDRINUSE)
	fatal := errors.New("unrelated fatal bind")
	tests := map[string]struct {
		domain  pairDomain
		fixed   bool
		failTCP bool
		cause   error
		wantTCP int
		wantUDP int
	}{
		"error: native known exclusion probes":  {domain: pairDomain{excluded: []portRange{{12345, 12345}}}, cause: collision, wantTCP: attempts},
		"error: native TCP exhaustion":          {failTCP: true, cause: collision, wantTCP: attempts},
		"error: native UDP exhaustion":          {cause: collision, wantTCP: attempts, wantUDP: attempts},
		"error: fixed TCP refusal":              {fixed: true, failTCP: true, cause: collision, wantTCP: 1},
		"error: fixed UDP refusal":              {fixed: true, cause: collision, wantTCP: 1, wantUDP: 1},
		"error: unrelated TCP failure":          {failTCP: true, cause: fatal, wantTCP: 1},
		"error: unrelated UDP failure":          {cause: fatal, wantTCP: 1, wantUDP: 1},
		"error: non-Windows permission failure": {cause: syscall.EACCES, wantTCP: 1, wantUDP: 1},
		"error: all excluded":                   {domain: pairDomain{available: true, bounds: portRange{50000, 51000}, excluded: []portRange{{50000, 51000}}}, cause: collision},
		"error: disjoint bounds":                {domain: pairDomain{available: true, bounds: portRange{51000, 50000}}, cause: collision},
		"error: wide exclusion bypass":          {domain: pairDomain{available: true, bounds: portRange{50000, 51000}, excluded: []portRange{{50000, 50999}}}, cause: collision, wantTCP: 1, wantUDP: 1},
		"error: overlapping exclusions":         {domain: pairDomain{available: true, bounds: portRange{50000, 50099}, excluded: []portRange{{50000, 50060}, {50040, 50098}}}, cause: collision, wantTCP: 1, wantUDP: 1},
		"error: empty exclusion table":          {domain: pairDomain{available: true, bounds: portRange{50000, 50099}}, cause: collision, wantTCP: attempts, wantUDP: attempts},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tcpCalls, udpCalls, closes := 0, 0, 0
			selected := make(map[int]bool)
			address := "127.0.0.1:0"
			if test.fixed {
				address = "127.0.0.1:12345"
			}
			tcp, udp, err := listenPair(t.Context(), "tcp4", address, pairListeners{
				domain:    func(context.Context) (pairDomain, error) { return test.domain, nil },
				retryable: collisionPairBind,
				listen: func(ctx context.Context, network, address string) (net.Listener, error) {
					if ctx != t.Context() || network != "tcp4" {
						t.Errorf("unexpected TCP context/network: %s", network)
					}
					if !test.failTCP && closes != tcpCalls {
						t.Fatalf("retry occurred before rollback: closes=%d binds=%d", closes, tcpCalls)
					}
					tcpCalls++
					if test.failTCP {
						return nil, test.cause
					}
					_, number, err := net.SplitHostPort(address)
					if err != nil {
						t.Fatal(err)
					}
					port, err := strconv.Atoi(number)
					if err != nil {
						t.Fatal(err)
					}
					if test.domain.available {
						if port < test.domain.bounds.first || port > test.domain.bounds.last || inPortRanges(port, test.domain.excluded) || selected[port] {
							t.Fatalf("invalid/repeated domain candidate %d", port)
						}
						selected[port] = true
					}
					return &portListener{closes: &closes}, nil
				},
				listenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
					if ctx != t.Context() || network != "udp4" || address != ":12345" {
						t.Errorf("unexpected UDP arguments: %s %s", network, address)
					}
					udpCalls++
					return nil, test.cause
				},
			})
			if tcp != nil || udp != nil || err == nil {
				t.Fatalf("failure returned sockets/error: %v %v %v", tcp, udp, err)
			}
			if _, ok := errors.AsType[*net.OpError](err); !ok {
				t.Fatalf("error is not typed: %T", err)
			}
			if (test.failTCP || test.wantUDP != 0) && !errors.Is(err, test.cause) {
				t.Fatalf("lost wrapped bind cause: %v", err)
			}
			wantCloses := test.wantTCP
			if test.failTCP {
				wantCloses = 0
			}
			if diff := gocmp.Diff([]int{test.wantTCP, test.wantUDP, wantCloses}, []int{tcpCalls, udpCalls, closes}); diff != "" {
				t.Fatalf("bind/close tallies (-want +got):\n%s", diff)
			}
		})
	}
}

func TestListenPairCandidateSelectionFailure(t *testing.T) {
	cause := errors.New("candidate entropy unavailable")
	tests := map[string]struct {
		index int
		cause error
	}{
		"error: entropy failure": {cause: cause},
		"error: negative index":  {index: -1},
		"error: oversized index": {index: 2},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tcp, udp, err := listenPair(t.Context(), "tcp4", "127.0.0.1:0", pairListeners{
				domain: func(context.Context) (pairDomain, error) {
					return pairDomain{bounds: portRange{first: 49152, last: 49153}}, nil
				},
				choose: func(size int) (int, error) {
					if size != 2 {
						t.Fatalf("candidate count = %d, want 2", size)
					}
					return test.index, test.cause
				},
				listen: func(context.Context, string, string) (net.Listener, error) {
					t.Fatal("invalid selection attempted a TCP bind")
					return nil, nil
				},
			})
			if tcp != nil || udp != nil || err == nil {
				t.Fatalf("invalid selection returned sockets/error: %v %v %v", tcp, udp, err)
			}
			if _, ok := errors.AsType[*net.OpError](err); !ok {
				t.Fatalf("invalid selection error is not typed: %T", err)
			}
			if test.cause != nil && !errors.Is(err, test.cause) {
				t.Fatalf("entropy failure lost its cause: %v", err)
			}
		})
	}
}

func TestListenPairInvalidAddress(t *testing.T) {
	tests := map[string]struct{ network, address string }{
		"error: implicit family":   {"tcp", "127.0.0.1:0"},
		"error: non-TCP network":   {"udp4", "127.0.0.1:0"},
		"error: missing host":      {"tcp4", ":0"},
		"error: service port":      {"tcp4", "127.0.0.1:http"},
		"error: signed port":       {"tcp4", "127.0.0.1:+1"},
		"error: oversized port":    {"tcp4", "127.0.0.1:65536"},
		"error: IPv6 host on IPv4": {"tcp4", "[::1]:0"},
		"error: IPv4 host on IPv6": {"tcp6", "127.0.0.1:0"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tcp, udp, err := listenPair(t.Context(), test.network, test.address, pairListeners{})
			if tcp != nil || udp != nil || err == nil {
				t.Fatalf("invalid input returned pair: %v %v %v", tcp, udp, err)
			}
			if _, ok := errors.AsType[*net.OpError](err); !ok {
				t.Fatalf("invalid input error not typed: %T", err)
			}
		})
	}
}

func TestPairBindErrorClassification(t *testing.T) {
	tests := map[string]struct {
		cause     error
		collision bool
		retryable bool
	}{
		"success: POSIX collision":          {cause: syscall.EADDRINUSE, collision: true, retryable: true},
		"success: native Winsock collision": {cause: syscall.Errno(10048), collision: runtime.GOOS == "windows", retryable: runtime.GOOS == "windows"},
		"success: native Winsock exclusion": {cause: syscall.Errno(10013), retryable: runtime.GOOS == "windows"},
		"error: arbitrary permission":       {cause: syscall.EACCES},
		"error: unrelated native code":      {cause: syscall.Errno(10014)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := fmt.Errorf("wrapped bind: %w", &net.OpError{Op: "listen", Net: "tcp4", Err: test.cause})
			if diff := gocmp.Diff([]bool{test.collision, test.retryable}, []bool{collisionPairBind(err), retryablePairBind(err)}); diff != "" {
				t.Fatalf("bind classification (-want +got):\n%s", diff)
			}
		})
	}
}

func TestListenPairFixedOccupied(t *testing.T) {
	lc := new(net.ListenConfig)
	busy, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	tcp, udp, err := ListenPair(t.Context(), "tcp4", busy.Addr().String())
	if tcp != nil || udp != nil || !collisionPairBind(err) {
		t.Fatalf("occupied fixed pair: %v %v %v", tcp, udp, err)
	}
}

func TestListenPairDiscoveryCancellation(t *testing.T) {
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	calls := 0
	discovery := newPairDiscovery(func() pairDomain {
		calls++
		close(started)
		<-release
		close(finished)
		return pairDomain{available: true, bounds: portRange{50000, 50000}}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		tcp, udp, err := listenPair(ctx, "tcp4", "127.0.0.1:0", pairListeners{domain: discovery})
		if tcp != nil || udp != nil {
			result <- errors.New("cancelled discovery returned sockets")
			return
		}
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancellation cause: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("cancelled caller did not return promptly")
	}
	close(release)
	<-finished
	domain, err := discovery(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(pairDomain{available: true, bounds: portRange{50000, 50000}}, domain, gocmp.AllowUnexported(pairDomain{}, portRange{})); diff != "" {
		t.Fatal(diff)
	}
	if calls != 1 {
		t.Fatalf("discovery workers = %d, want 1", calls)
	}
}

func TestParseDynamicPorts(t *testing.T) {
	tests := map[string]struct {
		output string
		want   portRange
		fail   bool
	}{
		"success: reported bounds": {output: "Protocol tcp Dynamic Port Range\nStart Port : 49152\nNumber of Ports : 16384\n", want: portRange{49152, 65535}},
		"error: missing bounds":    {output: "unreadable", fail: true},
		"error: malformed bound":   {output: "Start Port : nope\nNumber of Ports : 5\n", fail: true},
		"error: out of domain":     {output: "Start Port : 65535\nNumber of Ports : 2\n", fail: true},
		"error: zero count":        {output: "Start Port : 49152\nNumber of Ports : 0\n", fail: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseDynamicPorts(test.output)
			if (err != nil) != test.fail {
				t.Fatalf("bounds error: %v", err)
			}
			if diff := gocmp.Diff(test.want, got, gocmp.AllowUnexported(portRange{})); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
