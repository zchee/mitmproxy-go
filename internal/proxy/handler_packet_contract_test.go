// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

func TestHandlePacketTransportContract(t *testing.T) {
	tests := map[string]struct {
		wrap    func(layer.PacketTransport) layer.PacketTransport
		nilConn bool
	}{
		"success: pointer adapter preserves packet lifecycle": {wrap: func(conn layer.PacketTransport) layer.PacketTransport { return &externalPackets{PacketTransport: conn} }},
		"success: value adapter preserves packet lifecycle":   {wrap: func(conn layer.PacketTransport) layer.PacketTransport { return externalPackets{PacketTransport: conn} }},
		"error: nil interface":                                {nilConn: true, wrap: func(layer.PacketTransport) layer.PacketTransport { return nil }},
		"error: nil adapter pointer":                          {nilConn: true, wrap: func(layer.PacketTransport) layer.PacketTransport { return (*externalPackets)(nil) }},
		"error: nil tuple pointer":                            {nilConn: true, wrap: func(layer.PacketTransport) layer.PacketTransport { return (*packettransport.TupleConn)(nil) }},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			recorder := new(addontest.Recorder)
			const payload = "packet transport contract"
			bind := &bindAddon{t: t, ids: make(chan string, 1), run: func(ctx context.Context, c *layer.Context) error {
				c.ClientPackets.StopRecording()
				buf := make([]byte, 64)
				n, _, err := c.ClientPackets.ReadFrom(buf)
				if err != nil {
					return err
				}
				if diff := gocmp.Diff(payload, string(buf[:n])); diff != "" {
					return errors.New(diff)
				}
				return c.Do(ctx, func(context.Context) error {
					if c.Data.Client.ProxyMode != "dns" {
						return errors.New("packet transport lost proxy mode metadata")
					}
					return nil
				})
			}}
			runner := newHookRunner(t, recorder, bind)
			registry := new(Connections)
			h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: registry})
			if err != nil {
				t.Fatal(err)
			}
			// A runtime signature check reaches a behavioral failure on older
			// handlers rather than making the regression overlay fail to compile.
			handle, ok := any(h.HandlePackets).(func(context.Context, layer.PacketTransport, string, hookdata.LayerSpec) error)
			if !ok {
				t.Fatal("HandlePackets requires a concrete tuple instead of PacketTransport")
			}
			var conn layer.PacketTransport
			if !test.nilConn {
				conn, _ = acceptedPackets(t, []byte(payload))
			}
			conn = test.wrap(conn)
			err = handle(t.Context(), conn, "dns", hookdata.LayerSpec{Kind: topKind})
			if test.nilConn {
				if err == nil || err.Error() != "proxy: HandlePackets with a nil connection" {
					t.Fatalf("nil packet transport error = %v", err)
				}
				if len(clientLifecycleHooks(recorder)) != 0 {
					t.Fatal("nil packet transport emitted lifecycle hooks")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff([]string{"client_connected", "client_disconnected"}, clientLifecycleHooks(recorder)); diff != "" {
					t.Fatal(diff)
				}
				if conn.Context().Err() == nil {
					t.Fatal("finished packet transport was not closed")
				}
			}
			if registry.Len() != 0 {
				t.Fatal("packet transport remains registered")
			}
		})
	}
}

// externalPackets exercises a non-tuple implementation of the packet contract
// while forwarding to real UDP transports instead of simulating a service.
type externalPackets struct{ layer.PacketTransport }
