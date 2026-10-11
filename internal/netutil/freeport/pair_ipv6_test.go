// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestListenPairIPv6CandidateSelection(t *testing.T) {
	tests := map[string]struct {
		random   bool
		failTCP  bool
		failures int
		code     syscall.Errno
		fixed    bool
		wantErr  bool
	}{
		"success: platform IPv6 candidate strategy": {random: randomIPv6PairCandidates},
		"success: contiguous UDP exclusions":        {random: true, failures: 8, code: 10013},
		"success: contiguous TCP exclusions":        {random: true, failTCP: true, failures: 8, code: 10013},
		"success: UDP collisions":                   {random: true, failures: 8, code: 10048},
		"success: TCP collisions":                   {random: true, failTCP: true, failures: 8, code: 10048},
		"error: all UDP candidates excluded":        {random: true, failures: attempts, code: 10013, wantErr: true},
		"error: all TCP candidates excluded":        {random: true, failTCP: true, failures: attempts, code: 10013, wantErr: true},
		"error: fixed UDP exclusion":                {random: true, failures: 8, code: 10013, fixed: true, wantErr: true},
		"error: fixed TCP exclusion":                {random: true, failTCP: true, failures: 8, code: 10013, fixed: true, wantErr: true},
		"error: unrelated UDP refusal":              {random: true, failures: 8, code: 10014, wantErr: true},
		"error: unrelated TCP refusal":              {random: true, failTCP: true, failures: 8, code: 10014, wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			lc := new(net.ListenConfig)
			liveTCP, liveUDP, err := listenPair(t.Context(), "tcp6", "[::1]:0", pairListeners{
				listen: lc.Listen, listenPacket: lc.ListenPacket,
				retryable: windowsPairBindFixture, randomIPv6: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = liveTCP.Close(); _ = liveUDP.Close() })
			livePort := liveTCP.Addr().(*net.TCPAddr).Port
			remaining := make([]int, 65536-49152)
			for i := range remaining {
				remaining[i] = 49152 + i
			}
			seen := make(map[int]bool)
			tcpCalls, udpCalls, closes := 0, 0, 0
			var boundAddress string
			address := "[::1]:0"
			if test.fixed {
				address = liveTCP.Addr().String()
			}
			cause := fmt.Errorf("wrapped IPv6 bind: %w", &os.SyscallError{Syscall: "bind", Err: test.code})
			listeners := pairListeners{
				randomIPv6: test.random,
				domain: func(context.Context) (pairDomain, error) {
					t.Fatal("IPv6 invoked IPv4 discovery")
					return pairDomain{}, nil
				},
				choose: func(size int) (int, error) {
					index := 0
					if tcpCalls < test.failures {
						if remaining[index] == livePort {
							index++
						}
					} else {
						index = slices.Index(remaining, livePort)
					}
					if size != len(remaining) || index < 0 {
						t.Fatalf("candidate sampler lost the live port: size=%d remaining=%d", size, len(remaining))
					}
					remaining[index] = remaining[size-1]
					remaining = remaining[:size-1]
					return index, nil
				},
				retryable: windowsPairBindFixture,
				listen: func(ctx context.Context, network, requested string) (net.Listener, error) {
					if ctx != t.Context() || network != "tcp6" || closes != min(tcpCalls, test.failures) && !test.failTCP {
						t.Fatalf("TCP context/family/rollback mismatch: network=%s binds=%d closes=%d", network, tcpCalls, closes)
					}
					host, number, err := net.SplitHostPort(requested)
					port, parseErr := strconv.Atoi(number)
					if err != nil || parseErr != nil || host != "::1" {
						t.Fatalf("invalid IPv6 candidate: %s", requested)
					}
					if test.fixed {
						if requested != address {
							t.Fatalf("fixed candidate changed: %s", requested)
						}
					} else if test.random {
						if port < 49152 || port > 65535 || seen[port] {
							t.Fatalf("invalid or repeated explicit candidate: %s", requested)
						}
						seen[port] = true
					} else if port != 0 {
						t.Fatalf("non-Windows IPv6 did not use native :0: %s", requested)
					}
					tcpCalls++
					if tcpCalls <= test.failures {
						if test.failTCP {
							return nil, cause
						}
						boundAddress = requested
						return &pairedPortListener{address: &net.TCPAddr{IP: net.IPv6loopback, Port: port}, closes: &closes}, nil
					}
					if test.random && port != livePort {
						t.Fatalf("success candidate=%d want live=%d", port, livePort)
					}
					boundAddress = liveTCP.Addr().String()
					return liveTCP, nil
				},
				listenPacket: func(ctx context.Context, network, requested string) (net.PacketConn, error) {
					if ctx != t.Context() || network != "udp6" || requested != boundAddress {
						t.Fatalf("UDP identity mismatch: %s %s want %s", network, requested, boundAddress)
					}
					udpCalls++
					if tcpCalls <= test.failures {
						return nil, cause
					}
					return liveUDP, nil
				},
			}
			if test.failures == attempts {
				listeners.choose = nil
			}
			tcp, udp, err := listenPair(t.Context(), "tcp6", address, listeners)
			wantTCP, wantUDP, wantCloses := test.failures+1, test.failures+1, test.failures
			if test.wantErr {
				wantTCP = 1
				if test.failures == attempts {
					wantTCP = attempts
				}
				wantUDP, wantCloses = wantTCP, wantTCP
				if tcp != nil || udp != nil || !errors.Is(err, cause) {
					t.Fatalf("refusal lost sockets/cause: %v %v %v", tcp, udp, err)
				}
				if _, ok := errors.AsType[*net.OpError](err); !ok {
					t.Fatalf("refusal is not typed: %T", err)
				}
			} else if err != nil || tcp != liveTCP || udp != liveUDP {
				t.Fatalf("retry did not return live IPv6 pair: %v %v %v", tcp, udp, err)
			}
			if test.failTCP {
				wantUDP, wantCloses = 0, 0
				if !test.wantErr {
					wantUDP = 1
				}
			}
			if diff := gocmp.Diff([]int{wantTCP, wantUDP, wantCloses}, []int{tcpCalls, udpCalls, closes}); diff != "" {
				t.Fatalf("IPv6 bind/rollback tallies (-want +got):\n%s", diff)
			}
			if test.failures == attempts {
				want := fmt.Sprintf("paired acquisition exhausted: candidates=64 TCP_binds=64 UDP_binds=%d:", wantUDP)
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("exhaustion lost tallies: %v", err)
				}
			} else if err != nil && strings.Contains(err.Error(), "exhausted") {
				t.Fatalf("fail-fast refusal labelled as exhaustion: %v", err)
			}
		})
	}
}
