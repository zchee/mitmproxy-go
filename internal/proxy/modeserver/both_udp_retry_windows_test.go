// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
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
		"rejected ephemeral candidate closes TCP":         {failure: windows.WSAEACCES, failures: 1, wantCalls: 2},
		"synthetic failure then real UDP collision":       {failure: windows.WSAEACCES, failures: 1, realCollision: true, wantCalls: 2},
		"access denied exhausts the bounded candidates":   {failure: windows.WSAEACCES, failures: 64, wantCalls: 64},
		"explicit port preserves access denied":           {failure: windows.WSAEACCES, failures: 1, fixed: true, wantCalls: 1},
		"other permission error is not retried":           {failure: windows.ERROR_ACCESS_DENIED, failures: 1, wantCalls: 1},
		"same port success unchanged":                     {failure: windows.WSAEACCES, wantCalls: 1},
		"wrapped native collision retries":                {failure: fmt.Errorf("socket: %w", windows.WSAEADDRINUSE), failures: 1, wantCalls: 2},
		"wrapped native access denial retries":            {failure: fmt.Errorf("socket: %w", windows.WSAEACCES), failures: 1, wantCalls: 2},
		"wrapped invented POSIX collision does not retry": {failure: fmt.Errorf("socket: %w", syscall.EADDRINUSE), failures: 1, wantCalls: 1},
		"wrapped Win32 access denial does not retry":      {failure: fmt.Errorf("socket: %w", windows.ERROR_ACCESS_DENIED), failures: 1, wantCalls: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) { checkSharedUDPBind(t, tt) })
	}
}

func TestWindowsSharedTCPAccessDenied(t *testing.T) {
	tests := map[string]struct {
		cause     error
		spec      string
		noCursor  bool
		failures  int
		wantCalls int
		wantUDP   int
	}{
		"candidate access denial retries":                  {cause: windows.WSAEACCES, failures: 1, wantCalls: 2, wantUDP: 1},
		"candidate collision retries":                      {cause: windows.WSAEADDRINUSE, failures: 1, wantCalls: 2, wantUDP: 1},
		"candidate access denial exhausts":                 {cause: windows.WSAEACCES, failures: sharedPortAttempts, wantCalls: sharedPortAttempts},
		"candidate collision exhausts":                     {cause: windows.WSAEADDRINUSE, failures: sharedPortAttempts, wantCalls: sharedPortAttempts},
		"fixed access denial fails immediately":            {cause: windows.WSAEACCES, spec: "dns@127.0.0.1:50321", failures: 1, wantCalls: 1},
		"fixed collision fails immediately":                {cause: windows.WSAEADDRINUSE, spec: "dns@127.0.0.1:50321", failures: 1, wantCalls: 1},
		"invented collision fails immediately":             {cause: syscall.EADDRINUSE, failures: 1, wantCalls: 1},
		"Win32 access denial fails immediately":            {cause: windows.ERROR_ACCESS_DENIED, failures: 1, wantCalls: 1},
		"unrelated TCP failure preserves cause":            {cause: errors.New("TCP failure"), failures: 1, wantCalls: 1},
		"native allocator access denial fails immediately": {cause: windows.WSAEACCES, noCursor: true, failures: 1, wantCalls: 1},
		"native allocator collision fails immediately":     {cause: windows.WSAEADDRINUSE, noCursor: true, failures: 1, wantCalls: 1},
		"hostname access denial fails immediately":         {cause: windows.WSAEACCES, spec: "dns@localhost:0", failures: 1, wantCalls: 1},
		"hostname collision fails immediately":             {cause: windows.WSAEADDRINUSE, spec: "dns@localhost:0", failures: 1, wantCalls: 1},
		"IPv6 access denial fails immediately":             {cause: windows.WSAEACCES, spec: "dns@[::1]:0", failures: 1, wantCalls: 1},
		"IPv6 collision fails immediately":                 {cause: windows.WSAEADDRINUSE, spec: "dns@[::1]:0", failures: 1, wantCalls: 1},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			spec := test.spec
			if spec == "" {
				spec = "dns@127.0.0.1:0"
			}
			instance := makeInstance(t, spec, cfg)
			requested := instance.port
			calls, udpCalls, draws := 0, 0, 0
			selects := test.spec == "" && !test.noCursor
			instance.portCandidates = nil
			if !test.noCursor {
				instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
					if !selects {
						t.Fatal("non-candidate path selected a cursor")
					}
					return candidateCursor(func(context.Context) (int, error) {
						draws++
						if draws > sharedPortAttempts {
							t.Fatal("TCP retry exceeded the shared budget")
						}
						return 50000 + draws, nil
					}), nil
				}
			}
			cause := fmt.Errorf("TCP bind: %w", test.cause)
			instance.listenTCP = func(_ context.Context, _, address string) (net.Listener, error) {
				calls++
				_, number, err := net.SplitHostPort(address)
				if err != nil {
					t.Fatal(err)
				}
				wantPort := requested
				if selects {
					wantPort = 50000 + draws
				}
				if number != strconv.Itoa(wantPort) {
					t.Fatalf("TCP requested %s, want port %d", address, wantPort)
				}
				if calls <= test.failures {
					return nil, cause
				}
				return &candidateTestTCP{address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wantPort}}, nil
			}
			instance.listenUDP = func(_ context.Context, _, address string) (net.PacketConn, error) {
				udpCalls++
				addr, err := net.ResolveUDPAddr("udp4", address)
				if err != nil {
					t.Fatal(err)
				}
				return &candidateTestUDP{address: addr}, nil
			}
			streams, packets, err := instance.listenBothSockets(t.Context())
			wantDraws := 0
			if selects {
				wantDraws = test.wantCalls
			}
			if calls != test.wantCalls || udpCalls != test.wantUDP || draws != wantDraws || instance.port != requested {
				t.Fatalf("TCP_binds=%d UDP_binds=%d draws=%d requested=%d; want %d/%d/%d/%d; error=%v", calls, udpCalls, draws, instance.port, test.wantCalls, test.wantUDP, wantDraws, requested, err)
			}
			if test.wantUDP == 0 {
				if !errors.Is(err, cause) || len(streams) != 0 || len(packets) != 0 {
					t.Fatalf("TCP failure lost cause or acquired sockets: %v", err)
				}
				if selects && test.wantCalls == sharedPortAttempts && !strings.Contains(err.Error(), "candidates=64 TCP_binds=64 UDP_binds=0") {
					t.Fatalf("TCP exhaustion lost separate syscall tallies: %v", err)
				}
			} else if err != nil || len(streams) != 1 || len(packets) != 1 {
				t.Fatalf("retry did not complete Both: %v TCP=%d UDP=%d", err, len(streams), len(packets))
			}
			for _, stream := range streams {
				_ = stream.Close()
			}
			for _, packet := range packets {
				_ = packet.Close()
			}
			if isAddrInUse(fmt.Errorf("socket: %w", windows.WSAEACCES)) {
				t.Fatal("global address-in-use classification expanded to access denial")
			}
			t.Logf("TCP_binds=%d UDP_binds=%d", calls, udpCalls)
		})
	}
	t.Run("TCP and UDP share budget and terminal ownership", func(t *testing.T) {
		tests := map[string]struct {
			tcpFailures int
			cancel      bool
			domain      int
			wantTCP     int
			wantUDP     int
			wantCloses  int
			cause       error
		}{
			"mixed exhaustion":                  {tcpFailures: sharedPortAttempts - 1, wantTCP: sharedPortAttempts, wantUDP: 1, wantCloses: 1, cause: windows.WSAEACCES},
			"cancel after TCP refusal":          {tcpFailures: 1, cancel: true, wantTCP: 1, cause: context.Canceled},
			"cursor exhausts after TCP refusal": {tcpFailures: 1, domain: 1, wantTCP: 1, cause: io.EOF},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				cfg, _, _ := fixture(t)
				instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				draws, tcpCalls, udpCalls, closes := 0, 0, 0, 0
				instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
					return candidateCursor(func(context.Context) (int, error) {
						if test.domain != 0 && draws == test.domain {
							return 0, io.EOF
						}
						draws++
						return 50000 + draws, nil
					}), nil
				}
				instance.listenTCP = func(_ context.Context, _, address string) (net.Listener, error) {
					tcpCalls++
					if tcpCalls <= test.tcpFailures {
						if test.cancel {
							cancel()
						}
						return nil, fmt.Errorf("TCP bind: %w", windows.WSAEACCES)
					}
					addr, err := net.ResolveTCPAddr("tcp4", address)
					if err != nil {
						t.Fatal(err)
					}
					return &candidateTestTCP{address: addr, closes: &closes}, nil
				}
				instance.listenUDP = func(context.Context, string, string) (net.PacketConn, error) {
					udpCalls++
					return nil, fmt.Errorf("UDP bind: %w", windows.WSAEACCES)
				}
				streams, packets, err := instance.listenBothSockets(ctx)
				if !errors.Is(err, test.cause) || draws != test.wantTCP || tcpCalls != test.wantTCP || udpCalls != test.wantUDP || closes != test.wantCloses || len(streams) != 0 || len(packets) != 0 {
					t.Fatalf("terminal acquisition: draws=%d TCP_binds=%d UDP_binds=%d closes=%d error=%v", draws, tcpCalls, udpCalls, closes, err)
				}
				if test.domain != 0 && !errors.Is(err, windows.WSAEACCES) {
					t.Fatalf("cursor exhaustion lost TCP cause: %v", err)
				}
				if test.wantTCP == sharedPortAttempts && !strings.Contains(err.Error(), "candidates=64 TCP_binds=64 UDP_binds=1") {
					t.Fatalf("mixed exhaustion lost per-protocol tallies: %v", err)
				}
			})
		}
	})
	t.Run("wildcard TCP rollback before next candidate", func(t *testing.T) {
		cfg, _, _ := fixture(t)
		instance := makeInstance(t, "dns@0", cfg)
		draws, tcpCalls, udpCalls, closes := 0, 0, 0, 0
		instance.portCandidates = func(context.Context) (portCandidateCursor, error) {
			return candidateCursor(func(context.Context) (int, error) {
				if closes != draws {
					t.Fatal("next candidate selected before partial TCP rollback")
				}
				draws++
				return 50000 + draws, nil
			}), nil
		}
		instance.listenTCP = func(_ context.Context, network, address string) (net.Listener, error) {
			tcpCalls++
			if network == "tcp6" && draws == 1 {
				return nil, fmt.Errorf("TCP6 bind: %w", windows.WSAEACCES)
			}
			addr, err := net.ResolveTCPAddr(network, address)
			if err != nil {
				t.Fatal(err)
			}
			return &candidateTestTCP{address: addr, closes: &closes}, nil
		}
		instance.listenUDP = func(_ context.Context, network, address string) (net.PacketConn, error) {
			udpCalls++
			addr, err := net.ResolveUDPAddr(network, address)
			if err != nil {
				t.Fatal(err)
			}
			return &candidateTestUDP{address: addr}, nil
		}
		streams, packets, err := instance.listenBothSockets(t.Context())
		if err != nil || draws != 2 || tcpCalls != 4 || udpCalls != 2 || closes != 1 || instance.port != 0 || len(streams) != 2 || len(packets) != 2 {
			t.Fatalf("wildcard rollback: draws=%d TCP_binds=%d UDP_binds=%d closes=%d TCP=%d UDP=%d error=%v", draws, tcpCalls, udpCalls, closes, len(streams), len(packets), err)
		}
		for _, stream := range streams {
			if stream.Addr().(*net.TCPAddr).Port != 50002 {
				t.Fatal("retry TCP set does not share the next candidate")
			}
			_ = stream.Close()
		}
		for _, packet := range packets {
			if packet.LocalAddr().(*net.UDPAddr).Port != 50002 {
				t.Fatal("retry UDP set does not share the next candidate")
			}
			_ = packet.Close()
		}
		if closes != 3 {
			t.Fatalf("TCP closes=%d, want exactly 3", closes)
		}
	})
}
