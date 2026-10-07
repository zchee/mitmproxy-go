// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestWireGuardDestinationHandoff(t *testing.T) {
	tests := map[string]struct {
		strategy     string
		transport    connection.TransportProtocol
		missing      bool
		connectError bool
		wantCalls    int
	}{
		"eager stream opens before selection": {strategy: "eager", transport: connection.TCP, wantCalls: 1},
		"lazy stream waits for its child":     {strategy: "lazy", transport: connection.TCP},
		"datagram uses packet selection":      {strategy: "eager", transport: connection.UDP},
		"error: missing destination":          {strategy: "eager", transport: connection.TCP, missing: true},
		"error: eager origin failure":         {strategy: "eager", transport: connection.TCP, connectError: true, wantCalls: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := newContext(t, "wireguard")
			if err := c.Data.Options.Set(t.Context(), "connection_strategy="+tt.strategy); err != nil {
				t.Fatal(err)
			}
			if !tt.missing {
				c.Data.Server.Address = &connection.Address{Host: "192.0.2.42", Port: 443}
			}
			c.Data.Server.TransportProtocol = tt.transport
			l := build(t, c, "wireguard")
			_, server := layertest.Pipe(t)
			failure := errors.New("origin refused")
			actual := c.Data.Server.Clone()
			p := &pool{actual: actual, dial: func(ctx context.Context, _ *connection.Server) (layer.Conn, error) {
				if err := c.Do(ctx, func(context.Context) error { return nil }); err != nil {
					return nil, err
				}
				if tt.connectError {
					return nil, failure
				}
				return server, nil
			}}
			c.Pool = p
			selected := false
			c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
				selected = true
				if p.calls != tt.wantCalls {
					t.Fatalf("opens before selection = %d, want %d", p.calls, tt.wantCalls)
				}
				if tt.wantCalls > 0 && (c.Server == nil || c.Data.Server != actual) {
					t.Fatal("eager origin not published")
				}
				return &childLayer{run: func(context.Context, *layer.Context) error { return nil }}, nil
			}
			err := run(t, l, c)
			if tt.missing || tt.connectError {
				if err == nil || selected {
					t.Fatalf("failed startup = %v, selected=%v", err, selected)
				}
				if tt.connectError && !errors.Is(err, failure) {
					t.Fatalf("origin failure = %v", err)
				}
				return
			}
			if err != nil || !selected {
				t.Fatalf("handoff = %v, selected=%v", err, selected)
			}
		})
	}
}
