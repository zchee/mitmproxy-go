// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

type pairProbeListener struct {
	net.Listener
	address *net.TCPAddr
}

func (l *pairProbeListener) Addr() net.Addr { return l.address }

func TestWindowsListenPairUnavailableDomainRetries(t *testing.T) {
	tests := map[string]struct {
		code     syscall.Errno
		failTCP  bool
		failures int
		fixed    bool
		wantErr  bool
		native   bool
		random   bool
	}{
		"error: randomized fallback exhausts UDP exclusions": {code: 10013, failures: attempts, wantErr: true, random: true},
		"error: randomized fallback exhausts TCP exclusions": {code: 10013, failTCP: true, failures: attempts, wantErr: true, random: true},
		"success: native UDP exclusions remain retryable":    {code: 10013, failures: 3, native: true},
		"success: native TCP exclusions remain retryable":    {code: 10013, failTCP: true, failures: 3, native: true},
		"success: unavailable domain retries UDP exclusions": {code: 10013, failures: 3},
		"success: unavailable domain retries TCP exclusions": {code: 10013, failTCP: true, failures: 3},
		"success: unavailable domain retries UDP collisions": {code: 10048, failures: 3},
		"success: unavailable domain retries TCP collisions": {code: 10048, failTCP: true, failures: 3},
		"error: unavailable domain exhausts UDP exclusions":  {code: 10013, failures: attempts, wantErr: true},
		"error: unavailable domain exhausts TCP exclusions":  {code: 10013, failTCP: true, failures: attempts, wantErr: true},
		"error: fixed UDP exclusion is not retried":          {code: 10013, failures: 3, fixed: true, wantErr: true},
		"error: fixed TCP exclusion is not retried":          {code: 10013, failTCP: true, failures: 3, fixed: true, wantErr: true},
		"error: unrelated UDP failure is not retried":        {code: 10014, failures: 3, wantErr: true},
		"error: unrelated TCP failure is not retried":        {code: 10014, failTCP: true, failures: 3, wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			liveTCP, liveUDP, err := ListenPair(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = liveTCP.Close(); _ = liveUDP.Close() })
			livePort := liveTCP.Addr().(*net.TCPAddr).Port
			domain := pairDomain{}
			if !test.native {
				domain.bounds = portRange{first: livePort, last: livePort + test.failures}
				if domain.bounds.last > 65535 {
					domain.bounds = portRange{first: livePort - test.failures, last: livePort}
				}
			}
			if test.random {
				domain.bounds = portRange{first: 49152, last: 65535}
			}
			selected := make(map[int]bool)
			lc := new(net.ListenConfig)
			tcpCalls, udpCalls, domainCalls := 0, 0, 0
			var boundAddress string
			var partials []net.Listener
			assertClosed := func() {
				for _, partial := range partials {
					if err := partial.(*net.TCPListener).SetDeadline(time.Now()); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Fatal(err)
					}
					accepted, err := partial.Accept()
					if accepted != nil {
						_ = accepted.Close()
					}
					if !errors.Is(err, net.ErrClosed) {
						t.Fatalf("partial listener was not closed before retry/return: %v", err)
					}
				}
			}
			address := "127.0.0.1:0"
			if test.fixed {
				address = "127.0.0.1:49152"
			}
			cause := fmt.Errorf("wrapped native bind: %w", &net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "bind", Err: test.code}})
			listeners := pairListeners{
				domain: func(context.Context) (pairDomain, error) {
					domainCalls++
					return domain, nil
				},
				choose: func(size int) (int, error) {
					if domain.bounds.last == livePort && size > 1 {
						return size - 2, nil
					}
					return size - 1, nil
				},
				retryable: retryablePairBind,
				listen: func(ctx context.Context, network, requested string) (net.Listener, error) {
					if ctx != t.Context() || network != "tcp4" {
						t.Fatalf("unexpected TCP context/network: %s", network)
					}
					if test.fixed || test.native {
						if requested != address {
							t.Fatalf("unexpected native/fixed TCP address: %s", requested)
						}
					} else {
						host, number, err := net.SplitHostPort(requested)
						if err != nil {
							t.Fatal(err)
						}
						port, err := strconv.Atoi(number)
						if err != nil || host != "127.0.0.1" || port < domain.bounds.first || port > domain.bounds.last || selected[port] {
							t.Fatalf("invalid/repeated explicit candidate: %s", requested)
						}
						selected[port] = true
						if tcpCalls == test.failures && port != livePort {
							t.Fatalf("success candidate %d does not match live pair %d", port, livePort)
						}
					}
					assertClosed()
					tcpCalls++
					if tcpCalls <= test.failures {
						if test.failTCP {
							return nil, cause
						}
						partial, err := lc.Listen(ctx, network, "127.0.0.1:0")
						if err != nil {
							t.Fatal(err)
						}
						boundAddress = partial.Addr().String()
						partials = append(partials, partial)
						t.Cleanup(func() { _ = partial.Close() })
						if !test.native {
							bound, err := net.ResolveTCPAddr(network, requested)
							if err != nil {
								t.Fatal(err)
							}
							boundAddress = bound.String()
							return &pairProbeListener{Listener: partial, address: bound}, nil
						}
						return partial, nil
					}
					boundAddress = liveTCP.Addr().String()
					return liveTCP, nil
				},
				listenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
					if ctx != t.Context() || network != "udp4" || address != boundAddress {
						t.Fatalf("unexpected UDP context/network/address: %s %s", network, address)
					}
					udpCalls++
					if tcpCalls <= test.failures {
						return nil, cause
					}
					return liveUDP, nil
				},
			}
			if test.random {
				listeners.choose = nil
			}
			tcp, udp, err := listenPair(t.Context(), "tcp4", address, listeners)
			assertClosed()
			wantDomain := 1
			if test.fixed {
				wantDomain = 0
			}
			if diff := gocmp.Diff(wantDomain, domainCalls); diff != "" {
				t.Fatalf("unavailable-domain discovery tally (-want +got):\n%s", diff)
			}
			wantTCP, wantUDP := test.failures+1, test.failures+1
			if test.wantErr {
				wantTCP = 1
				if test.failures == attempts {
					wantTCP = attempts
				}
				wantUDP = wantTCP
				if tcp != nil || udp != nil || !errors.Is(err, cause) {
					t.Fatalf("bind refusal lost sockets/cause: %v %v %v", tcp, udp, err)
				}
				if _, ok := errors.AsType[*net.OpError](err); !ok {
					t.Fatalf("bind refusal is not typed: %T", err)
				}
			} else if err != nil || tcp != liveTCP || udp != liveUDP {
				t.Fatalf("retry did not return the live pair: %v %v %v", tcp, udp, err)
			}
			if test.failTCP {
				wantUDP = 1
				if test.wantErr {
					wantUDP = 0
				}
			}
			if diff := gocmp.Diff([]int{wantTCP, wantUDP}, []int{tcpCalls, udpCalls}); diff != "" {
				t.Fatalf("unavailable-domain bind tallies (-want +got):\n%s", diff)
			}
			if test.failures == attempts {
				want := fmt.Sprintf("paired acquisition exhausted: candidates=%d TCP_binds=%d UDP_binds=%d:", attempts, wantTCP, wantUDP)
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("exhaustion lost bind tallies: %v", err)
				}
			} else if err != nil && strings.Contains(err.Error(), "exhausted") {
				t.Fatalf("fail-fast refusal labelled as exhaustion: %v", err)
			}
			if !test.wantErr {
				client, err := net.DialTimeout("tcp4", tcp.Addr().String(), time.Second)
				if err != nil {
					t.Fatalf("returned TCP listener is not live: %v", err)
				}
				_ = client.Close()
				if _, err := udp.WriteToUDP([]byte("live pair"), udp.LocalAddr().(*net.UDPAddr)); err != nil {
					t.Fatalf("returned UDP socket is not live: %v", err)
				}
			}
		})
	}
}

func TestWindowsListenPairNativeCollision(t *testing.T) {
	tests := map[string]struct{ fixed bool }{
		"success: retry native collision for ephemeral request": {},
		"error: fixed native collision preserves cause":         {fixed: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			lc := new(net.ListenConfig)
			cause := fmt.Errorf("wrapped native bind: %w", &net.OpError{Op: "listen", Net: "tcp4", Err: syscall.Errno(10048)})
			tcpCalls, udpCalls := 0, 0
			address := "127.0.0.1:0"
			if test.fixed {
				address = "127.0.0.1:49152"
			}
			tcp, udp, err := listenPair(t.Context(), "tcp4", address, pairListeners{
				domain:    pairPortDomain,
				retryable: retryablePairBind,
				listen: func(ctx context.Context, network, address string) (net.Listener, error) {
					tcpCalls++
					if tcpCalls == 1 {
						return nil, cause
					}
					return lc.Listen(ctx, network, address)
				},
				listenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
					udpCalls++
					return lc.ListenPacket(ctx, network, address)
				},
			})
			if test.fixed {
				if tcp != nil || udp != nil || !errors.Is(err, cause) {
					t.Fatalf("fixed native refusal lost cause: %v %v %v", tcp, udp, err)
				}
				if _, ok := errors.AsType[*net.OpError](err); !ok {
					t.Fatalf("fixed error is not typed: %T", err)
				}
				if diff := gocmp.Diff([]int{1, 0}, []int{tcpCalls, udpCalls}); diff != "" {
					t.Fatal(diff)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tcp.Close(); _ = udp.Close() }()
			if tcpCalls < 2 || tcpCalls > attempts || udpCalls < 1 || udpCalls > attempts {
				t.Fatalf("native collision retry tally: TCP=%d UDP=%d", tcpCalls, udpCalls)
			}
			if diff := gocmp.Diff(tcp.Addr().String(), udp.LocalAddr().String()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
