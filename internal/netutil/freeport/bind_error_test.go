// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"net"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestFreePortBindErrorsAndRelease(t *testing.T) {
	tests := map[string]struct {
		failTCPAlways bool
		alternateTCP  bool
		wantUDP       int
	}{
		"error: TCP bind exhaustion":              {failTCPAlways: true},
		"error: UDP bind exhaustion":              {wantUDP: attempts},
		"error: joined last TCP and UDP failures": {alternateTCP: true, wantUDP: attempts / 2},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			lc := new(net.ListenConfig)
			busyTCP, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = busyTCP.Close() })
			busyUDP, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = busyUDP.Close() })
			var lastTCP, lastUDP error
			var reservations []string
			tcpCalls, udpCalls := 0, 0
			port, selectionErr := getFreePort(t.Context(), listeners{
				listen: func(ctx context.Context, network, address string) (net.Listener, error) {
					tcpCalls++
					if test.failTCPAlways || test.alternateTCP && tcpCalls%2 == 0 {
						conn, err := lc.Listen(ctx, network, busyTCP.Addr().String())
						lastTCP = err
						return conn, err
					}
					conn, err := lc.Listen(ctx, network, address)
					if err == nil {
						reservations = append(reservations, conn.Addr().String())
					}
					return conn, err
				},
				listenPacket: func(ctx context.Context, network, _ string) (net.PacketConn, error) {
					udpCalls++
					conn, err := lc.ListenPacket(ctx, network, busyUDP.LocalAddr().String())
					lastUDP = err
					return conn, err
				},
			})
			if port != 0 || selectionErr == nil {
				t.Fatalf("exhaustion = (%d, %v), want zero and a bind error", port, selectionErr)
			}
			for _, cause := range []error{lastTCP, lastUDP} {
				if cause != nil && !errors.Is(selectionErr, cause) {
					t.Fatalf("exhaustion error %v lost bind cause %v", selectionErr, cause)
				}
			}
			if diff := gocmp.Diff([]int{attempts, test.wantUDP}, []int{tcpCalls, udpCalls}); diff != "" {
				t.Fatalf("TCP/UDP attempts (-want +got):\n%s", diff)
			}
			for _, address := range reservations {
				conn, err := lc.Listen(t.Context(), "tcp4", address)
				if err != nil {
					t.Fatalf("exhausted TCP reservation %s was not released: %v", address, err)
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
