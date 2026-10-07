// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"net"
	"testing"
)

// Upstream test_dns_start_stop also requires both listener transports.
func TestBothProtocolStartStop(t *testing.T) {
	tests := map[string]struct{ spec string }{
		"standalone DNS": {"dns@127.0.0.1:0"},
		"reverse DNS":    {"reverse:dns://example.test@127.0.0.1:0"},
		"reverse HTTPS":  {"reverse:https://example.test@127.0.0.1:0"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			instance := makeInstance(t, tt.spec, cfg)
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			state := instance.state.Load()
			if len(state.listeners) != 1 || len(state.packetListeners) != 1 || len(state.addrs) != 2 {
				t.Fatalf("TCP=%d UDP=%d addresses=%v", len(state.listeners), len(state.packetListeners), state.addrs)
			}
			if state.addrs[0] != state.addrs[1] || state.addrs[0].Port == 0 {
				t.Fatalf("transports selected different addresses: %v", state.addrs)
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
				t.Fatal("Stop retained listener addresses")
			}
			stream, err := net.Listen("tcp4", state.addrs[0].String())
			if err != nil {
				t.Fatalf("Stop retained TCP socket: %v", err)
			}
			defer func() { _ = stream.Close() }()
			packet, err := net.ListenPacket("udp4", state.addrs[0].String())
			if err != nil {
				t.Fatalf("Stop retained UDP socket: %v", err)
			}
			defer func() { _ = packet.Close() }()
		})
	}
}
