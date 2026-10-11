// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"cmp"
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/netutil/freeport"
)

func TestAuthoritativePairRetry(t *testing.T) {
	tests := map[string]struct {
		network  string
		address  string
		occupied string
		cancel   bool
		invalid  bool
		wantErr  error
	}{
		"success: same port":               {},
		"success: IPv6 identity":           {network: "tcp6", address: "[::1]:0"},
		"error: fixed TCP port occupied":   {occupied: "tcp", wantErr: syscall.EADDRINUSE},
		"error: fixed UDP port occupied":   {occupied: "udp", wantErr: syscall.EADDRINUSE},
		"error: cancelled acquisition":     {cancel: true, wantErr: context.Canceled},
		"error: unrelated invalid address": {invalid: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			network := cmp.Or(test.network, "tcp4")
			address := cmp.Or(test.address, "127.0.0.1:0")
			if test.occupied != "" {
				busyTCP, busyUDP, err := freeport.ListenPair(t.Context(), "tcp4", address)
				if err != nil {
					t.Fatal(err)
				}
				address = busyUDP.LocalAddr().String()
				if test.occupied == "tcp" {
					_ = busyUDP.Close()
					t.Cleanup(func() { _ = busyTCP.Close() })
				} else {
					_ = busyTCP.Close()
					t.Cleanup(func() { _ = busyUDP.Close() })
				}
			}
			if test.invalid {
				address = "127.0.0.1:invalid"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancel {
				cancel()
			}
			tcp, udp, err := freeport.ListenPair(ctx, network, address)
			if tcp != nil {
				t.Cleanup(func() { _ = tcp.Close() })
			}
			if udp != nil {
				t.Cleanup(func() { _ = udp.Close() })
			}
			if test.wantErr != nil || test.invalid {
				if err == nil || tcp != nil || udp != nil {
					t.Fatalf("failed acquisition returned (%v, %v, %v)", tcp, udp, err)
				}
				if _, ok := errors.AsType[*net.OpError](err); !ok {
					t.Fatalf("acquisition error is not typed: %T", err)
				}
				if test.wantErr != nil && !errors.Is(err, test.wantErr) {
					t.Fatalf("acquisition lost cause %v: %v", test.wantErr, err)
				}
				if test.occupied == "udp" {
					listener, err := new(net.ListenConfig).Listen(t.Context(), "tcp4", address)
					if err != nil {
						t.Fatalf("failed pair retained the TCP socket: %v", err)
					}
					_ = listener.Close()
				}
				return
			}
			if err != nil || tcp == nil || udp == nil {
				t.Fatalf("successful acquisition returned (%v, %v, %v)", tcp, udp, err)
			}
			if diff := gocmp.Diff(tcp.Addr().String(), udp.LocalAddr().String()); diff != "" {
				t.Fatalf("pair identity (-TCP +UDP):\n%s", diff)
			}
			wantHost, _, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			gotHost, _, err := net.SplitHostPort(udp.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(wantHost, gotHost); diff != "" {
				t.Fatalf("pair host (-want +got):\n%s", diff)
			}
			cancel()
			peer, err := net.DialTimeout(network, tcp.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("caller cancellation closed the owned TCP socket: %v", err)
			}
			_ = peer.Close()
			if err := udp.SetReadDeadline(time.Time{}); err != nil {
				t.Fatalf("caller cancellation closed the owned UDP socket: %v", err)
			}
		})
	}
}
