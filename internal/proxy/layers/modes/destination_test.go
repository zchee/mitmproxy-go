// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

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
		killed       bool
		wantCalls    int
		wantLog      string
	}{
		"eager stream opens before selection": {strategy: "eager", transport: connection.TCP, wantCalls: 1},
		"lazy stream waits for its child":     {strategy: "lazy", transport: connection.TCP},
		"datagram uses packet selection":      {strategy: "eager", transport: connection.UDP},
		"error: missing destination":          {strategy: "eager", transport: connection.TCP, missing: true},
		"error: eager origin failure": {
			strategy: "eager", transport: connection.TCP, connectError: true, wantCalls: 1,
			wantLog: "server connection to 192.0.2.42:443 failed before connect",
		},
		"error: eager origin killed by addon": {
			strategy: "eager", transport: connection.TCP, connectError: true, killed: true, wantCalls: 1,
			wantLog: "server connection to 192.0.2.42:443 failed before connect",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := newContext(t, "wireguard")
			logs := &recordingHandler{Handler: slog.NewTextHandler(io.Discard, nil)}
			c.Logger = slog.New(logs)
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
			if tt.killed {
				failure = errors.New("proxy: connection killed: Request destination unknown. Unable to figure out where this request should be forwarded to.")
			}
			actual := c.Data.Server.Clone()
			p := &pool{actual: actual, dial: func(ctx context.Context, _ *connection.Server) (layer.Conn, error) {
				if err := c.Do(ctx, func(context.Context) error {
					if tt.killed {
						c.Data.Server.Error = new("Request destination unknown. Unable to figure out where this request should be forwarded to.")
					}
					return nil
				}); err != nil {
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
			var wantRecords []logRecord
			if tt.wantLog != "" {
				wantRecords = []logRecord{{Level: slog.LevelInfo, Message: tt.wantLog, Error: failure.Error()}}
			}
			if diff := gocmp.Diff(wantRecords, logs.records); diff != "" {
				t.Fatalf("connection logs (-want +got):\n%s", diff)
			}
			if tt.missing {
				if err == nil || selected {
					t.Fatalf("failed startup = %v, selected=%v", err, selected)
				}
				return
			}
			if err != nil || selected == tt.connectError {
				t.Fatalf("handoff = %v, selected=%v", err, selected)
			}
		})
	}
}
