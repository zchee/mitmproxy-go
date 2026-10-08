// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestHTTP3OriginRetention(t *testing.T) {
	tests := map[string]struct{ busy bool }{
		"idle failed entries make room":                          {},
		"borrowed and pending entries force unretained overflow": {busy: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			listener, target := newHTTP3RoutingListener(t)
			fixture, master := newTestStream(t, &streamAddon{})
			server := connection.NewServer(&connection.Address{Host: target.IP.String(), Port: target.Port})
			if err := master.Do(ctx, func(ctx context.Context) error {
				server.TransportProtocol, server.TLS = connection.UDP, true
				fixture.c.Data.Server = server
				return master.Addons.Add(ctx, &http3RoutingTLS{})
			}); err != nil {
				t.Fatal(err)
			}
			fixture.c.RecordPackets = proxy.RecordPackets
			fixture.c.OpenPackets = func(ctx context.Context, actual *connection.Server) (layer.PacketTransport, *connection.Server, error) {
				socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					return nil, nil, err
				}
				t.Cleanup(func() { _ = socket.Close() })
				return &http3RoutingPackets{PacketConn: socket, ctx: ctx, peer: target}, actual, nil
			}
			ownerCtx, cancel := context.WithCancel(ctx)
			origins := newHTTP3Origins(ownerCtx)
			defer func() { cancel(); origins.stop() }()
			peer, borrowed := newHTTP3ConsumerPeer(t, ctx, true)
			borrowedMetadata := connection.NewServer(&connection.Address{Host: "borrowed.example", Port: 443})
			// Borrowed sessions remain caller-owned even when unused. The other
			// entries model completed failures or outstanding dial flights.
			origins.borrow(borrowedMetadata, borrowed, nil)
			for i := range 99 {
				ready := make(chan struct{})
				if !test.busy {
					close(ready)
				}
				metadata := connection.NewServer(&connection.Address{Host: fmt.Sprintf("origin-%d.example", i), Port: 443})
				origins.entries[http3Key(metadata)] = &http3Origin{ready: ready, metadata: metadata, err: errors.New("completed dial failure")}
			}
			defer func() {
				origins.mu.Lock()
				defer origins.mu.Unlock()
				// Seeded dial states have no workers or owned sockets.
				for key, entry := range origins.entries {
					if entry.err != nil {
						delete(origins.entries, key)
					}
				}
			}()
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				conn, err := listener.Accept(ownerCtx)
				if err == nil {
					startHTTP3RoutingPeer(t, ownerCtx, conn)
				}
			}()
			defer func() { cancel(); <-joined }()
			endpoint, release, _, err := origins.acquire(ctx, fixture.c, server, &httpStream{id: 1})
			if err != nil {
				t.Fatal("full retained table refused a valid origin:", err)
			}
			if endpoint == nil || release == nil {
				t.Fatal("acquisition did not return a usable lease")
			}
			release()
			origins.mu.Lock()
			retained := len(origins.entries)
			_, keptNew := origins.entries[http3Key(server)]
			_, keptBorrowed := origins.entries[http3Key(borrowedMetadata)]
			// The seeded unfinished flights have no workers; retire their test
			// state before stopping so only actual sockets need to be joined.
			for key, entry := range origins.entries {
				if entry.err != nil {
					delete(origins.entries, key)
				}
			}
			origins.mu.Unlock()
			if retained != 100 || keptNew == test.busy || !keptBorrowed {
				t.Fatalf("retention = %d, new = %t, borrowed = %t", retained, keptNew, keptBorrowed)
			}
			if borrowed.Context().Err() != nil || peer.conn.Context().Err() != nil {
				t.Fatal("table evicted a caller-owned borrowed connection")
			}
		})
	}
}
