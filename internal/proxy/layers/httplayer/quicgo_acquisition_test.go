// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestHTTP3OriginCancelledWaiter(t *testing.T) {
	tests := map[string]struct{}{"cancelled waiter leaves shared establishment alive": {}}
	for name := range tests {
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
			entered, release := make(chan struct{}), make(chan struct{})
			fixture.c.RecordPackets = proxy.RecordPackets
			fixture.c.OpenPackets = func(ctx context.Context, actual *connection.Server) (layer.PacketTransport, *connection.Server, error) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
				if err := ctx.Err(); err != nil {
					return nil, nil, err
				}
				socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					return nil, nil, err
				}
				t.Cleanup(func() { _ = socket.Close() })
				return &http3RoutingPackets{PacketConn: socket, ctx: ctx, peer: target}, actual, nil
			}
			ownerCtx, cancelOwner := context.WithCancel(ctx)
			origins := newHTTP3Origins(ownerCtx)
			defer func() { cancelOwner(); origins.stop() }()
			waiterCtx, cancelWaiter := context.WithCancel(ctx)
			defer cancelWaiter()
			first := make(chan error, 1)
			firstJoined := make(chan struct{})
			go func() {
				defer close(firstJoined)
				_, release, _, err := origins.acquire(waiterCtx, fixture.c, server, &httpStream{id: 1})
				if release != nil {
					release()
				}
				first <- err
			}()
			defer func() { cancelWaiter(); <-firstJoined }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			cancelWaiter()
			select {
			case err := <-first:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled acquisition = %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			type acquired struct {
				endpoint ServerEndpoint
				release  func()
				err      error
			}
			second := make(chan acquired, 1)
			secondJoined := make(chan struct{})
			go func() {
				defer close(secondJoined)
				endpoint, release, _, err := origins.acquire(ctx, fixture.c, server, &httpStream{id: 2})
				second <- acquired{endpoint: endpoint, release: release, err: err}
			}()
			defer func() { cancelOwner(); <-secondJoined }()
			close(release)
			origin, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			startHTTP3RoutingPeer(t, ownerCtx, origin)
			select {
			case result := <-second:
				if result.err != nil {
					t.Fatal("shared origin establishment died with its first waiter:", result.err)
				}
				if _, ok := result.endpoint.(*http3Client); !ok {
					t.Fatalf("shared origin endpoint = %T", result.endpoint)
				}
				result.release()
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
