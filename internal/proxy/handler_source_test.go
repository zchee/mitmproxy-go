// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

type sourceDestinationConn struct {
	layer.Conn
	local    net.Addr
	endpoint string
}

// LocalAddr returns the accepted inner destination.
func (c *sourceDestinationConn) LocalAddr() net.Addr { return c.local }

// GetExtraInfo exposes the captured native destination when it is available.
func (c *sourceDestinationConn) GetExtraInfo(key string) (any, bool) {
	return c.endpoint, key == "remote_endpoint" && c.endpoint != ""
}

type sourceDestinationPackets struct {
	layer.PacketTransport
	local    net.Addr
	endpoint string
}

// LocalAddr returns the accepted inner destination.
func (c *sourceDestinationPackets) LocalAddr() net.Addr { return c.local }

// GetExtraInfo exposes the captured native destination when it is available.
func (c *sourceDestinationPackets) GetExtraInfo(key string) (any, bool) {
	return c.endpoint, key == "remote_endpoint" && c.endpoint != ""
}

func TestPacketSourceDestination(t *testing.T) {
	tests := map[string]struct {
		mode      string
		endpoint  string
		want      *connection.Address
		wantError string
	}{
		"wireguard inner destination":      {mode: "wireguard@127.0.0.1:0", want: &connection.Address{Host: "192.0.2.42", Port: 31337}},
		"tun inner destination":            {mode: "tun", want: &connection.Address{Host: "192.0.2.42", Port: 31337}},
		"local unresolved endpoint":        {mode: "local:curl", endpoint: "example.test:443", want: &connection.Address{Host: "example.test", Port: 443}},
		"local IPv6 endpoint":              {mode: "local", endpoint: "[2001:db8::42]:443", want: &connection.Address{Host: "2001:db8::42", Port: 443}},
		"regular destination preservation": {mode: "regular", endpoint: "example.test:443"},
		"reverse destination preservation": {mode: "reverse:http://example.test", endpoint: "example.test:443"},
		"custom mode preservation":         {mode: "user-defined", endpoint: "example.test:443"},
		"error: malformed native endpoint": {mode: "local", endpoint: "example.test", wantError: "invalid packet source remote endpoint"},
		"error: nonnumeric native port":    {mode: "local", endpoint: "example.test:bad", wantError: "invalid packet source remote endpoint address"},
		"error: out-of-range native port":  {mode: "local", endpoint: "example.test:65536", wantError: "invalid packet source remote endpoint address"},
	}
	for name, tt := range tests {
		for protocol, packets := range map[string]bool{"TCP": false, "UDP": true} {
			t.Run(name+"/"+protocol, func(t *testing.T) {
				observed := make(chan *connection.Address, 1)
				bind := &bindAddon{t: t, ids: make(chan string, 1), run: func(_ context.Context, c *layer.Context) error {
					observed <- c.Data.Server.Address
					return nil
				}}
				runner := newHookRunner(t, bind)
				registry := new(Connections)
				t.Cleanup(registry.Close)
				h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: registry})
				if err != nil {
					t.Fatal(err)
				}
				top := hookdata.LayerSpec{Kind: topKind}
				if packets {
					accepted, _ := acceptedPackets(t, []byte("initial"))
					conn := &sourceDestinationPackets{PacketTransport: accepted, local: &net.UDPAddr{IP: net.ParseIP("192.0.2.42"), Port: 31337}, endpoint: tt.endpoint}
					err = h.HandlePackets(t.Context(), conn, tt.mode, top)
				} else {
					peer, accepted := layertest.Pipe(t)
					t.Cleanup(func() { _ = peer.Close() })
					conn := &sourceDestinationConn{Conn: accepted, local: &net.TCPAddr{IP: net.ParseIP("192.0.2.42"), Port: 31337}, endpoint: tt.endpoint}
					err = h.Handle(t.Context(), conn, tt.mode, top)
				}
				if tt.wantError != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantError) {
						t.Fatalf("error = %v, want %q", err, tt.wantError)
					}
					if len(bind.ids) != 0 || len(observed) != 0 {
						t.Fatal("invalid source destination reached lifecycle hooks")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(tt.want, <-observed); diff != "" {
					t.Fatalf("destination before top layer (-want +got):\n%s", diff)
				}
			})
		}
	}
}
