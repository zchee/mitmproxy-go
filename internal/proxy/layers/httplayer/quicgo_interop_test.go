// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestHTTPTCPClientHTTP3Origin(t *testing.T) {
	tests := map[string]struct{ h2 bool }{
		"HTTP1 client": {},
		"HTTP2 client": {h2: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			listener, target := newHTTP3RoutingListener(t)
			session := newLayerSession(t, &streamAddon{})
			if err := session.m.Do(ctx, func(ctx context.Context) error {
				session.c.Data.Server.Address = &connection.Address{Host: target.IP.String(), Port: target.Port}
				session.c.Data.Server.TransportProtocol = connection.UDP
				session.c.Data.Server.TLS = true
				if test.h2 {
					session.c.Data.Client.ALPN = []byte("h2")
				}
				return session.m.Addons.Add(ctx, &http3RoutingTLS{})
			}); err != nil {
				t.Fatal(err)
			}
			session.c.RecordPackets = proxy.RecordPackets
			session.c.OpenPackets = func(ctx context.Context, server *connection.Server) (layer.PacketTransport, *connection.Server, error) {
				socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					return nil, nil, err
				}
				t.Cleanup(func() { _ = socket.Close() })
				return &http3RoutingPackets{PacketConn: socket, ctx: ctx, peer: target}, server, nil
			}
			consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
			runCtx, cancel := context.WithCancel(ctx)
			joined := make(chan struct{})
			go func() { defer close(joined); _ = consumer.Run(runCtx, session.c) }()
			var workers sync.WaitGroup
			defer func() { cancel(); _ = session.client.Close(); <-joined; workers.Wait() }()
			var client *h2.Endpoint
			var identity layer.StreamIdentity
			if test.h2 {
				var err error
				client, err = h2.New(session.client, h2.Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "interop client", Protocol: "h2"}, ValidateInboundHeaders: true})
				if err != nil {
					t.Fatal(err)
				}
				workers.Go(func() { _ = client.Run(runCtx) })
				identity, err = client.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := client.Send(ctx, h2.Event{Kind: h2.Headers, Identity: identity, Headers: []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "localhost"}, {Name: ":path", Value: "/echo"}, {Name: "content-length", Value: "3"}}}); err != nil {
					t.Fatal(err)
				}
				if err := client.Send(ctx, h2.Event{Kind: h2.Data, Identity: identity, Data: []byte("abc"), EndStream: true}); err != nil {
					t.Fatal(err)
				}
			} else {
				write(t, session.client, "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc")
			}
			origin, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			startHTTP3RoutingPeer(t, runCtx, origin)
			upstream, err := origin.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fields, body, _ := readHTTP3TestMessage(t, upstream)
			if len(fields) < 4 || fields[0].Value != "POST" || fields[2].Value != "/echo" {
				t.Fatal("origin request fields:", fields)
			}
			if diff := gocmp.Diff("abc", string(body)); diff != "" {
				t.Fatal(diff)
			}
			writeHTTP3TestHeaders(t, upstream, []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: "3"}})
			writeHTTP3TestFrame(t, upstream, 0, []byte("abc"))
			if err := upstream.Close(); err != nil {
				t.Fatal(err)
			}
			if test.h2 {
				body = nil
				for {
					event, err := client.ReceiveStream(ctx, identity)
					if err != nil {
						t.Fatal(err)
					}
					if event.Err != nil {
						t.Fatal(event.Err)
					}
					if event.Kind == h2.Headers && event.Headers[0].Value != "200" {
						t.Fatal("HTTP2 response status lost:", event)
					}
					body = append(body, event.Data...)
					if event.Receipt != nil {
						event.Receipt.Complete()
					}
					if event.EndStream {
						break
					}
				}
			} else {
				response, err := http.ReadResponse(bufio.NewReader(session.client), &http.Request{Method: "POST"})
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 200 || response.Proto != "HTTP/1.1" {
					t.Fatal("HTTP1 response status/version lost:", response)
				}
				body, err = io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if diff := gocmp.Diff("abc", string(body)); diff != "" {
				t.Fatal(diff)
			}
			if session.pool.openCount() != 0 {
				t.Fatal("HTTP3 origin used the TCP pool")
			}
			if err := session.m.Do(ctx, func(context.Context) error {
				if session.c.Data.Server.TLSVersion != connection.QUICv1 {
					return errors.New("origin QUIC version not published")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTP3ConsumerHTTP1Origin(t *testing.T) {
	tests := map[string]struct{ streamed bool }{
		"buffered request and response": {},
		"streamed request and response": {streamed: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			seen := make(chan *flow.HTTPFlow, 1)
			addon := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				switch name {
				case "requestheaders":
					f.Request.Scheme, f.Request.Host, f.Request.Port = "http", "mapped.test", 80
					f.Request.SetHostHeader("mapped.test")
					f.Request.Stream = test.streamed
				case "responseheaders":
					f.Response.Stream = test.streamed
				case "response":
					seen <- f
				}
			}}
			fixture, master := newTestStream(t, addon)
			pool := newPipePool(t)
			fixture.c.Pool, fixture.c.Record = pool, proxy.Record
			if err := master.Do(ctx, func(context.Context) error {
				fixture.c.Data.Server.Address = &connection.Address{Host: "example.com", Port: 443}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			peer, client := newHTTP3ConsumerPeer(t, ctx, false)
			_, server := newHTTP3ConsumerPeer(t, ctx, true)
			runCtx, cancel := context.WithCancel(ctx)
			joined := make(chan struct{})
			consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
			go func() { defer close(joined); _ = consumer.RunQUIC(runCtx, fixture.c, client, server) }()
			defer func() { cancel(); <-joined }()
			request, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, request, []qpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/echo"}, {Name: "content-length", Value: "3"}})
			writeHTTP3TestFrame(t, request, 0, []byte("abc"))
			if err := request.Close(); err != nil {
				t.Fatal(err)
			}
			var origin io.ReadWriter
			select {
			case origin = <-pool.origins:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			upstream, err := http.ReadRequest(bufio.NewReader(origin))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(upstream.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := upstream.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if upstream.Proto != "HTTP/1.1" || upstream.Host != "mapped.test" {
				t.Fatalf("origin request = %s host=%q", upstream.Proto, upstream.Host)
			}
			if diff := gocmp.Diff("abc", string(body)); diff != "" {
				t.Fatal(diff)
			}
			if _, err := fmt.Fprint(origin, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"); err != nil {
				t.Fatal(err)
			}
			fields, body, _ := readHTTP3TestMessage(t, request)
			if fields[0].Value != "200" {
				t.Fatal("HTTP/3 response status lost:", fields)
			}
			if diff := gocmp.Diff("abc", string(body)); diff != "" {
				t.Fatal(diff)
			}
			select {
			case f := <-seen:
				if err := master.Do(ctx, func(context.Context) error {
					if f.Request.HTTPVersion != "HTTP/3" || f.Response.HTTPVersion != "HTTP/1.1" || f.ServerConn.TransportProtocol != connection.TCP {
						return fmt.Errorf("mixed flow metadata: %s/%s/%s", f.Request.HTTPVersion, f.Response.HTTPVersion, f.ServerConn.TransportProtocol)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
