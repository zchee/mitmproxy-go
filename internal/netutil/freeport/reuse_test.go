// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"net"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestGetFreePortReusedCandidate(t *testing.T) {
	tests := map[string]struct {
		reserveUDP     bool
		reserveNextUDP bool
	}{
		"success: first candidate supports both protocols": {},
		"success: recycled UDP-busy candidate is excluded": {reserveUDP: true},
		"success: another new candidate is also UDP-busy":  {reserveUDP: true, reserveNextUDP: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			lc := new(net.ListenConfig)
			first, err := lc.Listen(t.Context(), "tcp4", ":0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = first.Close() })
			address := first.Addr().String()
			firstPort := first.Addr().(*net.TCPAddr).Port
			if test.reserveUDP {
				busy, err := lc.ListenPacket(t.Context(), "udp4", address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = busy.Close() })
			}
			calls, firstSelections := 0, 0
			nextReserved := false
			port, err := getFreePort(t.Context(), listeners{
				listen: func(ctx context.Context, network, requested string) (net.Listener, error) {
					calls++
					if calls == 1 {
						firstSelections++
						return first, nil
					}
					// A closed candidate may be chosen again by an ephemeral allocator.
					if recycled, err := lc.Listen(ctx, network, address); err == nil {
						firstSelections++
						return recycled, nil
					}
					candidate, err := lc.Listen(ctx, network, requested)
					if err == nil && test.reserveNextUDP && !nextReserved {
						busy, err := lc.ListenPacket(ctx, "udp4", candidate.Addr().String())
						if err != nil {
							_ = candidate.Close()
							t.Fatalf("reserve another UDP-busy candidate: %v", err)
						}
						t.Cleanup(func() { _ = busy.Close() })
						nextReserved = true
					}
					return candidate, err
				},
				listenPacket: lc.ListenPacket,
			})
			if err != nil {
				t.Fatalf("reused UDP-busy candidate exhausted %d attempts: %v", calls, err)
			}
			if port <= 0 || port > 65535 {
				t.Fatalf("selected port = %d, want a port in 1..65535", port)
			}
			if selected, err := FreePort(); err != nil || selected <= 0 || selected > 65535 {
				t.Fatalf("FreePort() = (%d, %v)", selected, err)
			}
			minimumCalls := 1
			if test.reserveUDP {
				minimumCalls = 2
				if port == firstPort {
					t.Fatal("selected the UDP-busy candidate")
				}
			}
			if test.reserveNextUDP {
				minimumCalls = 3
			}
			if calls < minimumCalls || calls > attempts {
				t.Fatalf("candidate attempts = %d, want %d..%d", calls, minimumCalls, attempts)
			}
			if diff := gocmp.Diff(1, firstSelections); diff != "" {
				t.Fatalf("initial candidate selections (-want +got):\n%s", diff)
			}
			released, err := lc.Listen(t.Context(), "tcp4", address)
			if err != nil {
				t.Fatalf("candidate TCP reservation was not released: %v", err)
			}
			if err := released.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
