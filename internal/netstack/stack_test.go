// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestStackLifecycle(t *testing.T) {
	tests := map[string]struct{ cancel bool }{
		"close":               {},
		"parent cancellation": {cancel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s, err := New(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if tt.cancel {
				cancel()
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := s.Inject([]byte{0x45}, nil); !errors.Is(err, ErrStackClosed) || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Inject after Close = %v", err)
			}
			if _, ok := <-s.Outbound(); ok {
				t.Fatal("outbound channel remains open")
			}
			if _, ok := <-s.TCPConns(); ok {
				t.Fatal("TCP accept channel remains open")
			}
			if _, ok := <-s.UDPConns(); ok {
				t.Fatal("UDP accept channel remains open")
			}
		})
	}
}

func TestInjectErrors(t *testing.T) {
	tests := map[string]struct{ packet []byte }{
		"empty":           {},
		"truncated IPv4":  {packet: []byte{0x45}},
		"truncated IPv6":  {packet: []byte{0x60}},
		"unknown version": {packet: make([]byte, 40)},
		"oversized":       {packet: make([]byte, 65576)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, err := New(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			if err := s.Inject(tt.packet, nil); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("Inject = %v, want invalid packet", err)
			}
		})
	}
}
