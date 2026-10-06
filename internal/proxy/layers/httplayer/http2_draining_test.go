// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestHTTP2OriginDraining(t *testing.T) {
	tests := map[string]struct{ code http2.ErrCode }{
		"success: accepted response drains on its old connection": {code: http2.ErrCodeNo},
		"error: written request is not replayed":                  {code: http2.ErrCodeProtocol},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			stream, manager := newTestStream(t, &streamAddon{})
			pool := newPipePool(t)
			stream.c.Pool, stream.c.Record = pool, proxy.Record
			ctx, cancel := context.WithCancel(t.Context())
			origins := newHTTPOrigins(ctx)
			var workers sync.WaitGroup
			t.Cleanup(func() { cancel(); origins.stop(); workers.Wait() })
			request, err := httpmsg.MakeRequest("GET", "https://example.com/", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			setup := func(ctx context.Context, conn layer.Conn, srv *connection.Server) (layer.Conn, error) {
				return conn, manager.Do(ctx, func(context.Context) error { srv.ALPN = []byte("h2"); return nil })
			}
			connect := func(s *httpStream) (*http2Client, *h2.Endpoint, <-chan struct{}) {
				t.Helper()
				if err := manager.Do(ctx, func(context.Context) error {
					s.flow = flow.NewHTTPFlow(s.c.Data.Client, s.c.Data.Server, true)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				type result struct {
					endpoint ServerEndpoint
					err      error
				}
				done := make(chan result, 1)
				lazy := &lazyServer{}
				go func() {
					endpoint, err := (&httpLayer{}).connect(ctx, s.c, s, request, nil, origins, setup, lazy)
					done <- result{endpoint, err}
				}()
				conn := await(t, pool.origins)
				peer, err := h2.New(conn, h2.Config{Descriptor: layer.EndpointDescriptor{Identity: "origin"}, ValidateInboundHeaders: true})
				if err != nil {
					t.Fatal(err)
				}
				finishedSending := make(chan struct{})
				workers.Go(func() {
					_ = peer.Run(ctx)
					if ctx.Err() == nil {
						if err := conn.CloseWrite(); err != nil {
							t.Errorf("origin half-close: %v", err)
						}
						// Run has interrupted its readers; restore reads to drain the socket before closing.
						if err := conn.SetReadDeadline(time.Time{}); err != nil {
							t.Errorf("origin drain deadline: %v", err)
						}
						stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) })
						close(finishedSending)
						_, err := io.Copy(io.Discard, conn)
						stop()
						if err != nil && ctx.Err() == nil {
							t.Errorf("origin socket drain: %v", err)
						}
					} else {
						close(finishedSending)
					}
					_ = conn.Close()
				})
				got := await(t, done)
				if got.err != nil {
					t.Fatal(got.err)
				}
				t.Cleanup(lazy.release)
				endpoint, ok := got.endpoint.(*http2Client)
				if !ok {
					t.Fatalf("origin endpoint = %T", got.endpoint)
				}
				return endpoint, peer, finishedSending
			}
			first, oldPeer, oldFinishedSending := connect(stream)
			if err := first.Send(ctx, RequestHeaders{ID: stream.id, Request: request, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			written, err := oldPeer.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := oldPeer.Send(ctx, h2.Event{Kind: h2.Headers, Identity: written.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "200"}}}); err != nil {
				t.Fatal(err)
			}
			if head, err := first.engine.ReceiveStream(ctx, first.identity); err != nil || head.Kind != h2.Headers {
				t.Fatalf("active response = %+v, %v", head, err)
			}
			if err := oldPeer.Shutdown(ctx, test.code, nil); err != nil {
				t.Fatal(err)
			}
			if test.code == http2.ErrCodeNo {
				if err := oldPeer.Send(ctx, h2.Event{Kind: h2.Data, Identity: written.Identity, Data: []byte("partial")}); err != nil {
					t.Fatal(err)
				}
				body, err := first.engine.ReceiveStream(ctx, first.identity)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff("partial", string(body.Data)); diff != "" {
					t.Fatal(diff)
				}
				body.Receipt.Complete()
			} else {
				reset, err := first.engine.ReceiveStream(ctx, first.identity)
				if err == nil {
					err = reset.Err
				}
				failure, ok := errors.AsType[*h2.StreamError](err)
				if !ok || failure.Code != test.code {
					t.Fatalf("written request GOAWAY = %+v, %v", reset, err)
				}
			}
			if _, err := first.engine.OpenStream(ctx); !errors.Is(err, h2.ErrDraining) {
				t.Fatalf("new stream after GOAWAY = %v", err)
			}
			derived := *stream.c
			derived.Server = nil
			if err := manager.Do(ctx, func(context.Context) error {
				data := *stream.c.Data
				data.Server = connection.NewServer(nil)
				derived.Data = &data
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			secondStream := &httpStream{c: &derived, id: 3}
			second, newPeer, _ := connect(secondStream)
			if second.engine == first.engine {
				t.Fatal("new request reused draining engine")
			}
			if diff := gocmp.Diff(2, pool.openCount()); diff != "" {
				t.Fatal(diff)
			}
			if err := second.Send(ctx, RequestHeaders{ID: 3, Request: request, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			fresh, err := newPeer.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := newPeer.Send(ctx, h2.Event{Kind: h2.Headers, Identity: fresh.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "204"}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			if response, err := second.engine.ReceiveStream(ctx, second.identity); err != nil || !response.EndStream {
				t.Fatalf("fresh response = %+v, %v", response, err)
			}
			if test.code == http2.ErrCodeNo {
				if err := oldPeer.Send(ctx, h2.Event{Kind: h2.Data, Identity: written.Identity, Data: []byte("tail"), EndStream: true}); err != nil {
					t.Fatal(err)
				}
				await(t, oldFinishedSending)
				body, err := first.engine.ReceiveStream(ctx, first.identity)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff("tail", string(body.Data)); diff != "" {
					t.Fatal(diff)
				}
				if !body.EndStream {
					t.Fatal("old response did not end")
				}
				body.Receipt.Complete()
			}
		})
	}
}
