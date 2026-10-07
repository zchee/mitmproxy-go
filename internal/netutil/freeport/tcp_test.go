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

func TestGetFreeTCPPort(t *testing.T) {
	tests := map[string]struct {
		failures  int
		wantCalls int
		wantPort  int
	}{
		"success: no UDP socket":           {wantCalls: 1, wantPort: 12345},
		"success: final candidate":         {failures: 63, wantCalls: 64, wantPort: 12345},
		"success: exhaustion returns zero": {failures: 64, wantCalls: 64},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			calls, closes, udpCalls := 0, 0, 0
			lc := listeners{
				listen: func(ctx context.Context, network, address string) (net.Listener, error) {
					if ctx != t.Context() {
						t.Error("TCP listener did not receive caller's context")
					}
					if diff := gocmp.Diff([]string{"tcp4", ":0"}, []string{network, address}); diff != "" {
						t.Errorf("TCP bind arguments (-want +got):\n%s", diff)
					}
					calls++
					if calls <= tt.failures {
						return nil, errors.New("TCP bind refused by test")
					}
					return &portListener{closes: &closes}, nil
				},
				listenPacket: func(context.Context, string, string) (net.PacketConn, error) {
					udpCalls++
					return nil, errors.New("UDP socket refused by test")
				},
			}
			if diff := gocmp.Diff(tt.wantPort, getFreeTCPPort(t.Context(), lc)); diff != "" {
				t.Errorf("selected port (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantCalls, calls); diff != "" {
				t.Errorf("TCP bind attempts (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(0, udpCalls); diff != "" {
				t.Errorf("UDP bind attempts (-want +got):\n%s", diff)
			}
			wantCloses := 0
			if tt.wantPort != 0 {
				wantCloses = 1
			}
			if diff := gocmp.Diff(wantCloses, closes); diff != "" {
				t.Errorf("TCP closes (-want +got):\n%s", diff)
			}
		})
	}
}
