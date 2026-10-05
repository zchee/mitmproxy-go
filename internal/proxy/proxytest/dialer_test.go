// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
)

func TestOriginDialerPreservesMetadata(t *testing.T) {
	origin := StartEchoOrigin(t)
	dial := originDialer(map[string]*Origin{"example.test": origin}, proxy.NewDialer(net.Dialer{}))
	tests := map[string]struct {
		host   string
		source *connection.Address
	}{
		"success: mapped target":      {host: "example.test"},
		"success: canonical DNS name": {host: "EXAMPLE.TEST."},
		"success: bound source":       {host: "example.test", source: &connection.Address{Host: "127.0.0.1"}},
		"success: wildcard source":    {host: "example.test", source: &connection.Address{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := connection.NewServer(&connection.Address{Host: tt.host, Port: 443})
			server.SNI = new("example.test")
			server.Sockname = tt.source
			before := server.Clone()
			conn, err := dial(t.Context(), server)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if diff := gocmp.Diff(before, server); diff != "" {
				t.Fatalf("dialer mutated target metadata (-before +after):\n%s", diff)
			}
			if diff := gocmp.Diff(origin.Addr, conn.RemoteAddr().String()); diff != "" {
				t.Fatalf("wire target (-origin +remote):\n%s", diff)
			}
			if source := conn.LocalAddr().(*net.TCPAddr).IP.String(); source != "127.0.0.1" {
				t.Fatalf("local source = %q, want loopback", source)
			}
		})
	}
}

func TestOriginDialerErrors(t *testing.T) {
	origin := StartEchoOrigin(t)
	dial := originDialer(map[string]*Origin{"example.test": origin}, proxy.NewDialer(net.Dialer{}))
	tests := map[string]struct {
		address   *connection.Address
		source    *connection.Address
		transport connection.TransportProtocol
		cancel    bool
		want      string
	}{
		"error: missing target":        {transport: connection.TCP, want: "server address unknown"},
		"error: empty host":            {address: &connection.Address{}, transport: connection.TCP, want: "server address unknown"},
		"error: unmapped test domain":  {address: &connection.Address{Host: "MISSING.TEST.", Port: 443}, transport: connection.TCP, want: "no origin mapped for missing.test"},
		"error: unsupported transport": {address: &connection.Address{Host: "example.test", Port: 443}, transport: connection.UDP, want: "unsupported transport"},
		"error: invalid source":        {address: &connection.Address{Host: "example.test", Port: 443}, source: &connection.Address{Host: "not-an-ip"}, transport: connection.TCP, want: "invalid source address"},
		"error: canceled dial":         {address: &connection.Address{Host: "example.test", Port: 443}, transport: connection.TCP, cancel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := connection.NewServer(tt.address)
			server.Sockname = tt.source
			server.TransportProtocol = tt.transport
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			conn, err := dial(ctx, server)
			if conn != nil {
				_ = conn.Close()
				t.Fatal("invalid dial returned a connection")
			}
			if err == nil {
				t.Fatal("invalid dial succeeded")
			}
			if tt.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("dial error = %v, want context.Canceled", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("dial error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestOriginDialerHonorsSourcePort(t *testing.T) {
	origin := StartEchoOrigin(t)
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	server := connection.NewServer(&connection.Address{Host: "example.test", Port: 443})
	server.Sockname = &connection.Address{Host: "127.0.0.1", Port: occupied.Addr().(*net.TCPAddr).Port}
	conn, err := originDialer(map[string]*Origin{"example.test": origin}, proxy.NewDialer(net.Dialer{}))(t.Context(), server)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("dial ignored the occupied explicit source port")
	}
}
