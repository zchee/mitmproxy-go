// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
)

func TestGetFreePort(t *testing.T) {
	port := GetFreePort()
	if port <= 0 || port > 65535 {
		t.Fatalf("GetFreePort() = %d, want a port in 1..65535", port)
	}
	// The port was free a moment ago; binding both protocols again must
	// work unless another process raced for it, which is unlikely enough
	// to treat as a failure.
	tcp, err := net.Listen("tcp4", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("binding TCP port %d returned by GetFreePort: %v", port, err)
	}
	defer func() {
		if err := tcp.Close(); err != nil {
			t.Errorf("closing TCP listener: %v", err)
		}
	}()
	udp, err := net.ListenPacket("udp4", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("binding UDP port %d returned by GetFreePort: %v", port, err)
	}
	if err := udp.Close(); err != nil {
		t.Errorf("closing UDP socket: %v", err)
	}
}

func TestGetFreePortNeverFails(t *testing.T) {
	tests := map[string]struct {
		failNetwork string
	}{
		"success: every bind fails":    {failNetwork: ""},
		"success: only UDP binds fail": {failNetwork: "udp4"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			calls := 0
			lc := &net.ListenConfig{
				Control: func(network, _ string, _ syscall.RawConn) error {
					calls++
					if tt.failNetwork == "" || network == tt.failNetwork {
						return errors.New("bind refused by test")
					}
					return nil
				},
			}
			if got := getFreePort(t.Context(), lc); got != 0 {
				t.Errorf("getFreePort() = %d, want 0", got)
			}
			if calls < attempts {
				t.Errorf("getFreePort() made %d bind attempts, want at least %d", calls, attempts)
			}
		})
	}
}
