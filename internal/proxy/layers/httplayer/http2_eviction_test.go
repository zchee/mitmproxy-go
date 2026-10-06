// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestHTTP2ClosedBorrowedOrigin(t *testing.T) {
	tests := map[string]struct {
		cancel bool
		want   error
	}{
		"success: closed transport rejects an unwritten lease": {want: errOriginInUse},
		"error: cancelled acquisition is not retried":          {cancel: true, want: context.Canceled},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			stream, manager := newTestStream(t, &streamAddon{})
			stream.c.Record = proxy.Record
			if err := manager.Do(t.Context(), func(context.Context) error {
				stream.c.Data.Server.ALPN = []byte("h2")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			request, err := httpmsg.MakeRequest("GET", "https://example.com/", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn, peer := layertest.Pipe(t)
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			origins := newHTTPOrigins(t.Context())
			t.Cleanup(origins.stop)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancel {
				cancel()
			}
			_, _, err = origins.acquire(ctx, stream.c, conn, stream.c.Data.Server, stream, request, nil)
			if !errors.Is(err, test.want) {
				t.Fatalf("closed borrowed origin = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHTTP2CompletedOriginEviction(t *testing.T) {
	tests := map[string]struct{ rotations int }{
		"success: completed graceful rotations on one client": {rotations: 16},
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
			for rotation := range test.rotations {
				derived := *stream.c
				derived.Server = nil
				data := *stream.c.Data
				data.Server = connection.NewServer(nil)
				derived.Data = &data
				exchange := &httpStream{c: &derived, id: StreamID(2*rotation + 1), flow: flow.NewHTTPFlow(data.Client, data.Server, true)}
				type result struct {
					endpoint ServerEndpoint
					err      error
				}
				done := make(chan result, 1)
				lazy := &lazyServer{}
				go func() {
					endpoint, err := (&httpLayer{}).connect(ctx, &derived, exchange, request, nil, origins, setup, lazy)
					done <- result{endpoint, err}
				}()
				conn := await(t, pool.origins)
				peer := http2.NewFramer(conn, conn)
				written := make(chan uint32, 1)
				peerDone := make(chan struct{})
				workers.Go(func() {
					defer close(peerDone)
					defer func() { _ = conn.Close() }()
					stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
					defer stop()
					preface := make([]byte, len(http2.ClientPreface))
					if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
						t.Errorf("origin preface = %q, %v", preface, err)
						return
					}
					if err := peer.WriteSettings(); err != nil {
						t.Error(err)
						return
					}
					for {
						frame, err := peer.ReadFrame()
						if err != nil {
							t.Error(err)
							return
						}
						switch frame := frame.(type) {
						case *http2.SettingsFrame:
							if !frame.IsAck() {
								if err := peer.WriteSettingsAck(); err != nil {
									t.Error(err)
									return
								}
							}
						case *http2.HeadersFrame:
							written <- frame.StreamID
							_, _ = io.Copy(io.Discard, conn)
							return
						}
					}
				})
				got := await(t, done)
				if got.err != nil {
					t.Fatal(got.err)
				}
				endpoint := got.endpoint.(*http2Client)
				if err := endpoint.Send(ctx, RequestHeaders{ID: exchange.id, Request: request, EndStream: true}); err != nil {
					t.Fatal(err)
				}
				streamID := await(t, written)
				if err := peer.WriteGoAway(streamID, http2.ErrCodeNo, nil); err != nil {
					t.Fatal(err)
				}
				var headers bytes.Buffer
				if err := hpack.NewEncoder(&headers).WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
					t.Fatal(err)
				}
				if err := peer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: headers.Bytes(), EndHeaders: true}); err != nil {
					t.Fatal(err)
				}
				if _, err := endpoint.engine.ReceiveStream(ctx, endpoint.identity); err != nil {
					t.Fatal(err)
				}
				if _, err := endpoint.engine.OpenStream(ctx); !errors.Is(err, h2.ErrDraining) {
					t.Fatalf("new lease after GOAWAY = %v", err)
				}
				origins.mu.Lock()
				retained := len(origins.entries)
				origins.mu.Unlock()
				if retained != 1 {
					t.Fatalf("rotation %d: draining origin membership = %d, want 1", rotation, retained)
				}
				if err := peer.WriteData(streamID, true, []byte("tail")); err != nil {
					t.Fatal(err)
				}
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				body, err := endpoint.engine.ReceiveStream(ctx, endpoint.identity)
				if err != nil || string(body.Data) != "tail" || !body.EndStream {
					t.Fatalf("accepted response = %+v, %v", body, err)
				}
				body.Receipt.Complete()
				lazy.release()
				joined := make(chan struct{})
				go func() { origins.workers.Wait(); close(joined) }()
				await(t, joined)
				await(t, peerDone)
				origins.mu.Lock()
				retained = len(origins.entries)
				origins.mu.Unlock()
				if retained != 0 {
					t.Fatalf("rotation %d: completed origin membership = %d, want 0", rotation, retained)
				}
			}
			if got := pool.openCount(); got != test.rotations {
				t.Fatalf("origin opens = %d, want %d", got, test.rotations)
			}
		})
	}
}
