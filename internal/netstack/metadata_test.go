// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
)

func TestStreamExtraInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conn, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	source := netip.MustParseAddrPort("192.168.86.134:12345")
	dest := netip.MustParseAddrPort("0.0.0.0:0")
	info := map[string]any{"original_src": source, "original_dst": dest, "pid": uint32(42), "process_name": "curl", "remote_endpoint": "example.test:443"}
	s := newStream(ctx, conn, nil, info)
	defer func() { cancel(); <-s.done }()
	clear(info)
	tests := map[string]struct {
		want    any
		present bool
	}{
		"transport_protocol": {want: connection.TCP, present: true},
		"peername":           {want: conn.RemoteAddr(), present: true},
		"sockname":           {want: conn.LocalAddr(), present: true},
		"original_src":       {want: source, present: true},
		"original_dst":       {want: dest, present: true},
		"pid":                {want: uint32(42), present: true},
		"process_name":       {want: "curl", present: true},
		"remote_endpoint":    {want: "example.test:443", present: true},
		"absent":             {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, present := s.GetExtraInfo(name)
			if present != tt.present {
				t.Fatalf("presence = %v, want %v", present, tt.present)
			}
			if diff := gocmp.Diff(tt.want, got, gocmp.Comparer(func(a, b netip.AddrPort) bool { return a == b })); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCopyExtraInfo(t *testing.T) {
	tests := map[string]struct {
		info    map[string]any
		invalid bool
	}{
		"nil":                     {},
		"immutable fields":        {info: map[string]any{"pid": uint32(42), "process_name": "curl", "original_src": netip.MustParseAddrPort("127.0.0.1:443")}},
		"mutable bytes":           {info: map[string]any{"tag": []byte("source")}},
		"unsupported type":        {info: map[string]any{"tag": make(chan int)}, invalid: true},
		"pid has wrong type":      {info: map[string]any{"pid": "42"}, invalid: true},
		"endpoint has wrong type": {info: map[string]any{"original_dst": "127.0.0.1:443"}, invalid: true},
		"process has wrong type":  {info: map[string]any{"process_name": []byte("curl")}, invalid: true},
		"oversized metadata":      {info: map[string]any{"tag": make([]byte, 65537)}, invalid: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := copyExtraInfo(tt.info)
			if tt.invalid {
				if !errors.Is(err, ErrInvalidPacket) {
					t.Fatalf("copy = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.info) {
				t.Fatalf("key count = %d, want %d", len(got), len(tt.info))
			}
			if bytes, ok := tt.info["tag"].([]byte); ok {
				clear(bytes)
				if value := string(got["tag"].([]byte)); value != "source" {
					t.Fatalf("copy retained caller bytes: %q", value)
				}
			}
		})
	}
}
