// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestLegacyPortCandidateSelection(t *testing.T) {
	selectors := map[string]struct {
		paired     bool
		selectPort func(context.Context, listeners) (int, error)
	}{
		"FreePort": {paired: true, selectPort: getFreePort},
		"GetFreePort": {paired: true, selectPort: func(ctx context.Context, lc listeners) (int, error) {
			port, _ := getFreePort(ctx, lc)
			return port, nil
		}},
		"GetFreeTCPPort": {selectPort: func(ctx context.Context, lc listeners) (int, error) {
			return getFreeTCPPort(ctx, lc), nil
		}},
	}
	cause := &net.OpError{Op: "listen", Net: "tcp4", Err: syscall.EADDRINUSE}
	tests := map[string]struct {
		domain    pairDomain
		choose    func(int) (int, error)
		failTCP   bool
		failUDP   bool
		wantPort  int
		wantBinds int
	}{
		"success: excluded block wider than budget": {
			domain:   pairDomain{available: true, bounds: portRange{49152, 49252}, excluded: []portRange{{49152, 49251}}},
			wantPort: 49252, wantBinds: 1,
		},
		"error: all excluded": {
			domain: pairDomain{available: true, bounds: portRange{49152, 65535}, excluded: []portRange{{49152, 65535}}},
		},
		"error: unavailable bounds use distinct randomized candidates": {
			domain: pairDomain{bounds: portRange{49152, 65535}}, failTCP: true, wantBinds: attempts,
		},
		"error: unavailable bounds still prefilter exclusions": {
			domain: pairDomain{bounds: portRange{49152, 65535}, excluded: []portRange{{49152, 60000}}}, failTCP: true, wantBinds: attempts,
		},
		"error: UDP failures release every TCP reservation": {
			domain: pairDomain{available: true, bounds: portRange{49152, 65535}},
			choose: func(int) (int, error) { return 0, nil }, failUDP: true, wantPort: 49152, wantBinds: attempts,
		},
		"error: small complement exhausts without repeated candidates": {
			domain: pairDomain{available: true, bounds: portRange{49152, 49154}}, failTCP: true, wantBinds: 3,
		},
		"error: invalid candidate index": {
			domain: pairDomain{available: true, bounds: portRange{49152, 65535}},
			choose: func(n int) (int, error) { return n, nil },
		},
		"error: random source failure": {
			domain: pairDomain{available: true, bounds: portRange{49152, 65535}},
			choose: func(int) (int, error) { return 0, cause },
		},
	}
	for selector, api := range selectors {
		t.Run(selector, func(t *testing.T) {
			for name, test := range tests {
				t.Run(name, func(t *testing.T) {
					seen := make(map[int]bool)
					tcpCloses, udpCloses, udpBinds := 0, 0, 0
					lc := listeners{
						domain: func(ctx context.Context, paired bool) (pairDomain, error) {
							if ctx != t.Context() || paired != api.paired {
								t.Fatalf("discovery context/pairing = %v/%t, want caller/%t", ctx, paired, api.paired)
							}
							return test.domain, nil
						},
						choose: test.choose,
						excluded: func(port int, paired bool) bool {
							if paired != api.paired {
								t.Fatalf("exclusion pairing = %t, want %t", paired, api.paired)
							}
							return inPortRanges(port, test.domain.excluded)
						},
						listen: func(ctx context.Context, network, address string) (net.Listener, error) {
							port, err := strconv.Atoi(strings.TrimPrefix(address, ":"))
							if err != nil || ctx != t.Context() || network != "tcp4" {
								t.Fatalf("invalid TCP bind: %s %s %v", network, address, err)
							}
							if port < test.domain.bounds.first || port > test.domain.bounds.last || inPortRanges(port, test.domain.excluded) || seen[port] {
								t.Fatalf("candidate %d outside complement or repeated: %+v", port, test.domain)
							}
							seen[port] = true
							if test.failTCP {
								return nil, fmt.Errorf("occupied TCP candidate: %w", cause)
							}
							return &pairedPortListener{address: &net.TCPAddr{Port: port}, closes: &tcpCloses}, nil
						},
						listenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
							port, err := strconv.Atoi(strings.TrimPrefix(address, ":"))
							if err != nil || ctx != t.Context() || network != "udp4" || !seen[port] || !api.paired {
								t.Fatalf("invalid paired UDP bind: %s %s %v", network, address, err)
							}
							udpBinds++
							if test.failUDP {
								return nil, fmt.Errorf("occupied UDP candidate: %w", cause)
							}
							return &portPacketConn{closes: &udpCloses}, nil
						},
					}
					port, err := api.selectPort(t.Context(), lc)
					wantPort, wantBinds := test.wantPort, test.wantBinds
					if test.failUDP {
						if api.paired {
							wantPort = 0
						} else {
							wantBinds = 1
						}
					}
					if diff := gocmp.Diff([]int{wantPort, wantBinds}, []int{port, len(seen)}); diff != "" {
						t.Fatalf("selected port/binds (-want +got):\n%s; error=%v", diff, err)
					}
					if selector == "FreePort" && wantPort == 0 {
						if err == nil || !strings.Contains(err.Error(), "no paired TCP/UDP port after 64 attempts:") {
							t.Fatalf("missing budget error: %v", err)
						}
						if (test.failTCP || test.failUDP || name == "error: random source failure") && !errors.Is(err, cause) {
							t.Fatalf("lost typed candidate cause: %v", err)
						}
					} else if err != nil {
						t.Fatalf("unexpected selector error: %v", err)
					}
					wantTCPCloses := wantBinds
					if test.failTCP {
						wantTCPCloses = 0
					}
					wantUDPCloses := 0
					if api.paired && wantPort != 0 {
						wantUDPCloses = 1
					}
					if diff := gocmp.Diff([]int{wantTCPCloses, wantUDPCloses}, []int{tcpCloses, udpCloses}); diff != "" {
						t.Fatalf("release-before-return closes (-want +got):\n%s", diff)
					}
					if !api.paired && udpBinds != 0 {
						t.Fatalf("TCP-only selector attempted %d UDP binds", udpBinds)
					}
				})
			}
		})
	}
}
