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

func TestGetFreePort(t *testing.T) {
	tests := map[string]struct {
		selectPort func() (int, error)
	}{
		"success: TCP and UDP":        {selectPort: FreePort},
		"success: legacy TCP and UDP": {selectPort: func() (int, error) { return GetFreePort(), nil }},
		"success: TCP only":           {selectPort: func() (int, error) { return GetFreeTCPPort(), nil }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			port, err := tt.selectPort()
			if err != nil {
				t.Fatalf("select port: %v", err)
			}
			if port <= 0 || port > 65535 {
				t.Fatalf("selected port = %d, want a port in 1..65535", port)
			}
		})
	}
}

func TestGetFreePortAttempts(t *testing.T) {
	tests := map[string]struct {
		failTCP     bool
		udpFailures int
		wantTCP     int
		wantUDP     int
		wantPort    int
	}{
		"success: both binds succeed":          {wantTCP: 1, wantUDP: 1, wantPort: 12345},
		"success: final candidate":             {udpFailures: 63, wantTCP: 64, wantUDP: 64, wantPort: 12345},
		"success: TCP exhaustion returns zero": {failTCP: true, wantTCP: 64},
		"success: UDP exhaustion returns zero": {udpFailures: 64, wantTCP: 64, wantUDP: 64},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tcpCalls, udpCalls := 0, 0
			tcpCloses, udpCloses := 0, 0
			lc := listeners{
				listen: func(ctx context.Context, network, address string) (net.Listener, error) {
					if ctx != t.Context() {
						t.Error("TCP listener did not receive caller's context")
					}
					if diff := gocmp.Diff([]string{"tcp4", ":0"}, []string{network, address}); diff != "" {
						t.Errorf("TCP bind arguments (-want +got):\n%s", diff)
					}
					tcpCalls++
					if tt.failTCP {
						return nil, errors.New("TCP bind refused by test")
					}
					return &portListener{closes: &tcpCloses}, nil
				},
				listenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
					if ctx != t.Context() {
						t.Error("UDP listener did not receive caller's context")
					}
					if diff := gocmp.Diff([]string{"udp4", ":12345"}, []string{network, address}); diff != "" {
						t.Errorf("UDP bind arguments (-want +got):\n%s", diff)
					}
					udpCalls++
					if udpCalls <= tt.udpFailures {
						return nil, errors.New("UDP bind refused by test")
					}
					return &portPacketConn{closes: &udpCloses}, nil
				},
			}
			port, err := getFreePort(t.Context(), lc)
			if got, want := err != nil, tt.wantPort == 0; got != want {
				t.Fatalf("selection error = %v, want exhaustion=%v", err, want)
			}
			if diff := gocmp.Diff(tt.wantPort, port); diff != "" {
				t.Errorf("selected port (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff([]int{tt.wantTCP, tt.wantUDP}, []int{tcpCalls, udpCalls}); diff != "" {
				t.Errorf("TCP/UDP bind attempts (-want +got):\n%s", diff)
			}
			wantTCPCloses, wantUDPCloses := 0, 0
			if !tt.failTCP {
				wantTCPCloses = tt.wantTCP
			}
			if tt.wantPort != 0 {
				wantUDPCloses = 1
			}
			if diff := gocmp.Diff([]int{wantTCPCloses, wantUDPCloses}, []int{tcpCloses, udpCloses}); diff != "" {
				t.Errorf("TCP/UDP closes (-want +got):\n%s", diff)
			}
		})
	}
}

// Embed the unused socket operations so an accidental call fails the test;
// only address selection and closing are part of the helper's contract.
type portListener struct {
	net.Listener
	closes *int
}

func (*portListener) Addr() net.Addr { return &net.TCPAddr{Port: 12345} }

func (l *portListener) Close() error {
	*l.closes++
	return nil
}

type portPacketConn struct {
	net.PacketConn
	closes *int
}

func (c *portPacketConn) Close() error {
	*c.closes++
	return nil
}
