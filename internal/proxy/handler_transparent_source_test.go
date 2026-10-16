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

type transparentSourceMetadata struct {
	value   any
	present bool
}

// LocalAddr returns the redirected listener, never a usable original destination.
func (*transparentSourceMetadata) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

// GetExtraInfo exposes captured metadata, including deliberately malformed inputs.
func (c *transparentSourceMetadata) GetExtraInfo(key string) (any, bool) {
	return c.value, key == "remote_endpoint" && c.present
}

func TestTransparentSourceDestination(t *testing.T) {
	tests := map[string]struct {
		value     any
		present   bool
		want      *connection.Address
		wantError string
	}{
		"IPv4 original destination":  {value: "192.0.2.42:443", present: true, want: &connection.Address{Host: "192.0.2.42", Port: 443}},
		"IPv6 original destination":  {value: "[2001:db8::42]:443", present: true, want: &connection.Address{Host: "2001:db8::42", Port: 443}},
		"mapped IPv4 normalization":  {value: "[::ffff:192.0.2.42]:80", present: true, want: &connection.Address{Host: "192.0.2.42", Port: 80}},
		"error: missing metadata":    {wantError: "transparent source has no original destination metadata"},
		"error: wrong metadata type": {value: connection.Address{Host: "192.0.2.42", Port: 443}, present: true, wantError: "remote endpoint must be a string"},
		"error: empty endpoint":      {value: "", present: true, wantError: "invalid packet source remote endpoint"},
		"error: missing port":        {value: "192.0.2.42", present: true, wantError: "invalid packet source remote endpoint"},
		"error: zero port":           {value: "192.0.2.42:0", present: true, wantError: "invalid packet source remote endpoint address"},
		"error: oversized port":      {value: "192.0.2.42:65536", present: true, wantError: "invalid packet source remote endpoint address"},
		"error: nonnumeric port":     {value: "192.0.2.42:no", present: true, wantError: "invalid packet source remote endpoint address"},
		"error: unresolved hostname": {value: "origin.test:443", present: true, wantError: "invalid transparent original destination address"},
		"error: unspecified IP":      {value: "0.0.0.0:443", present: true, wantError: "invalid transparent original destination address"},
		"error: multicast IP":        {value: "[ff02::1]:443", present: true, wantError: "invalid transparent original destination address"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := packetSourceDestination("transparent@127.0.0.1:8080", &transparentSourceMetadata{value: tt.value, present: tt.present})
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) || got != nil {
					t.Fatalf("destination = %v, error = %v; want no destination and %q", got, err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("captured destination (-want +got):\n%s", diff)
			}
		})
	}
	t.Run("Handler rejects metadata before hooks", func(t *testing.T) {
		tests := map[string]struct{ endpoint string }{
			"missing captured metadata": {},
			"invalid captured hostname": {endpoint: "listener.test:8080"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				observed := make(chan struct{}, 1)
				bind := &bindAddon{t: t, ids: make(chan string, 1), run: func(context.Context, *layer.Context) error {
					observed <- struct{}{}
					return nil
				}}
				runner := newHookRunner(t, bind)
				registry := new(Connections)
				t.Cleanup(registry.Close)
				handler, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: registry})
				if err != nil {
					t.Fatal(err)
				}
				peer, accepted := layertest.Pipe(t)
				t.Cleanup(func() { _ = peer.Close() })
				conn := &sourceDestinationConn{Conn: accepted, local: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}, endpoint: tt.endpoint}
				if err := handler.Handle(t.Context(), conn, "transparent", hookdata.LayerSpec{Kind: topKind}); err == nil {
					t.Fatal("Handler accepted absent or invalid original destination")
				}
				if len(bind.ids) != 0 || len(observed) != 0 {
					t.Fatal("invalid destination reached client hooks or a layer")
				}
			})
		}
	})
	t.Run("error: connection has no metadata interface", func(t *testing.T) {
		got, err := packetSourceDestination("transparent", new(net.TCPConn))
		if err == nil || !strings.Contains(err.Error(), "transparent source has no original destination metadata") || got != nil {
			t.Fatalf("destination = %v, error = %v; listener fallback must be refused", got, err)
		}
	})
}
