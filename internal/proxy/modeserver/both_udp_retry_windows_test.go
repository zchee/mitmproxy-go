// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSharedUDPAccessRetry(t *testing.T) {
	tests := map[string]struct {
		failure       error
		failures      int
		fixed         bool
		realCollision bool
		wantCalls     int
	}{
		"rejected ephemeral candidate closes TCP":       {failure: windows.WSAEACCES, failures: 1, wantCalls: 2},
		"synthetic failure then real UDP collision":     {failure: windows.WSAEACCES, failures: 1, realCollision: true, wantCalls: 2},
		"access denied exhausts the bounded candidates": {failure: windows.WSAEACCES, failures: 64, wantCalls: 64},
		"explicit port preserves access denied":         {failure: windows.WSAEACCES, failures: 1, fixed: true, wantCalls: 1},
		"other permission error is not retried":         {failure: windows.ERROR_ACCESS_DENIED, failures: 1, wantCalls: 1},
		"same port success unchanged":                   {failure: windows.WSAEACCES, wantCalls: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) { checkSharedUDPBind(t, tt) })
	}
}

func TestWindowsSharedTCPAccessDenied(t *testing.T) {
	tests := map[string]struct{}{"TCP permission error never enters UDP retry": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
			calls := 0
			instance.listenTCP = func(context.Context, string, string) (net.Listener, error) {
				calls++
				return nil, fmt.Errorf("TCP bind: %w", windows.WSAEACCES)
			}
			instance.listenUDP = func(context.Context, string, string) (net.PacketConn, error) {
				t.Error("TCP error reached UDP acquisition")
				return nil, windows.WSAEACCES
			}
			streams, packets, err := instance.listenBothSockets(t.Context())
			if calls != 1 || !errors.Is(err, windows.WSAEACCES) || len(streams) != 0 || len(packets) != 0 {
				t.Fatalf("TCP failure = %v, calls=%d", err, calls)
			}
			if isAddrInUse(fmt.Errorf("socket: %w", windows.WSAEACCES)) {
				t.Fatal("global address-in-use classification expanded to access denial")
			}
		})
	}
}
