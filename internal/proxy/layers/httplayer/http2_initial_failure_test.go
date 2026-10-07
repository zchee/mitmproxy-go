// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func headerLimitedOrigin(t *testing.T) *h2.Endpoint {
	t.Helper()
	transport, wire := net.Pipe()
	engine, err := h2.New(transport, h2.Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "origin"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	workers.Go(func() { _ = engine.Run(ctx) })
	workers.Go(func() {
		if err := func() error {
			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(wire, preface); err != nil {
				return err
			}
			if string(preface) != http2.ClientPreface {
				t.Errorf("origin preface = %q", preface)
				return nil
			}
			framer := http2.NewFramer(wire, wire)
			if err := framer.WriteSettings(http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 512}); err != nil {
				return err
			}
			for {
				frame, err := framer.ReadFrame()
				if err != nil {
					return err
				}
				switch frame := frame.(type) {
				case *http2.SettingsFrame:
					if !frame.IsAck() {
						if err := framer.WriteSettingsAck(); err != nil {
							return err
						}
					}
				case *http2.HeadersFrame:
					if frame.StreamID != 3 || !frame.HeadersEnded() || !frame.StreamEnded() {
						t.Errorf("origin request = %+v, want complete sibling stream 3", frame)
					}
					var block bytes.Buffer
					if err := hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "204"}); err != nil {
						return err
					}
					if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: frame.StreamID, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
						return err
					}
				case *http2.RSTStreamFrame:
					t.Errorf("unsent failed request emitted RST_STREAM: %+v", frame)
				case *http2.GoAwayFrame:
					t.Errorf("origin connection received GOAWAY: %+v", frame)
				}
			}
		}(); err != nil && ctx.Err() == nil {
			t.Errorf("origin wire: %v", err)
		}
	})
	t.Cleanup(func() { cancel(); _ = transport.Close(); _ = wire.Close(); workers.Wait() })
	return engine
}

func TestHTTP2InitialRequestFailureIsolation(t *testing.T) {
	tests := map[string]struct{ cancelled bool }{
		"error: rejected headers release sibling before error hook resumes": {},
		"error: cancelled send releases sibling before error hook resumes":  {cancelled: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			stream, manager := newTestStream(t, &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "error" {
					f.Intercept()
					close(entered)
				}
			}})
			engine := headerLimitedOrigin(t)
			id, err := engine.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			request, err := httpmsg.MakeRequest("GET", "https://example.com/", nil, httpmsg.Headers{{Name: []byte("x-large"), Value: []byte(strings.Repeat("x", 1024))}})
			if err != nil {
				t.Fatal(err)
			}
			head := RequestHeaders{ID: 1, Request: request, EndStream: true}
			drainStream(t, stream, head)
			server := &http2Client{engine: engine, identity: id, id: 1}
			ctx, cancel := context.WithCancel(t.Context())
			if test.cancelled {
				cancel()
			}
			err = server.Send(ctx, head)
			cancel()
			if err == nil || (test.cancelled && !errors.Is(err, context.Canceled)) {
				t.Fatalf("initial request Send = %v", err)
			}
			failure := ResponseProtocolError{ID: 1, Code: GenericServerError, Message: err.Error()}
			done := make(chan streamOutput, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				out, err := stream.handle(t.Context(), failure)
				if err != nil {
					t.Error(err)
				}
				done <- out
			}()
			await(t, entered)
			// The standalone owner has no endpoint-failure auto-resume observer.
			t.Cleanup(func() {
				_ = manager.Do(context.WithoutCancel(t.Context()), func(context.Context) error { stream.flow.Resume(); return nil })
				await(t, finished)
			})
			siblingID, err := engine.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			sibling := &http2Client{engine: engine, identity: siblingID, id: 3}
			request, err = httpmsg.MakeRequest("GET", "https://example.com/", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent := make(chan error, 1)
			go func() { sent <- sibling.Send(t.Context(), RequestHeaders{ID: 3, Request: request, EndStream: true}) }()
			if err := await(t, sent); err != nil {
				t.Fatal(err)
			}
			response, err := sibling.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if headers, ok := response.(ResponseHeaders); !ok || headers.Response.StatusCode != 204 {
				t.Fatalf("sibling response = %#v", response)
			}
			if err := manager.Do(t.Context(), func(context.Context) error {
				if !stream.flow.Intercepted() {
					t.Error("error hook resumed before sibling completed")
				}
				stream.flow.Resume()
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			out := await(t, done)
			if len(out.events) == 0 {
				t.Fatal("resumed error hook emitted no failure")
			}
			if diff := gocmp.Diff(failure, out.events[0]); diff != "" {
				t.Fatalf("resumed failure (-want +got):\n%s", diff)
			}
			if status, respond := failure.Code.HTTPStatusCode(); !respond || status != 502 {
				t.Fatalf("failed exchange status = %d, respond = %v", status, respond)
			}
		})
	}
}

func TestHTTP2InitialRequestFailureReceive(t *testing.T) {
	tests := map[string]struct{ cancelled bool }{
		"error: rejected initial headers preserve original receive error":  {},
		"error: cancelled initial headers preserve original receive error": {cancelled: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			engine := headerLimitedOrigin(t)
			id, err := engine.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			client := &http2Client{engine: engine, identity: id, id: 1}
			request, err := httpmsg.MakeRequest("GET", "https://example.com/", nil, httpmsg.Headers{{Name: []byte("x-large"), Value: []byte(strings.Repeat("x", 1024))}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancelled {
				cancel()
			}
			sendErr := client.Send(ctx, RequestHeaders{ID: 1, Request: request, EndStream: true})
			if sendErr == nil {
				t.Fatal("initial Send succeeded")
			}
			event, receiveErr := client.Receive(t.Context())
			if !errors.Is(receiveErr, sendErr) {
				t.Fatalf("Receive = %#v, %v; want original Send error %v", event, receiveErr, sendErr)
			}
		})
	}
}

func TestHTTP2InitialRequestFailureDriver(t *testing.T) {
	tests := map[string]struct{ lazy bool }{
		"error: local cleanup preserves intercepted error hook":       {},
		"error: lazy origin cleanup preserves intercepted error hook": {lazy: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered := make(chan struct{})
				stream, manager := newTestStream(t, &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
					if name == "error" {
						f.Intercept()
						close(entered)
					}
				}})
				peer, source := h2EndpointPair(t)
				engine := headerLimitedOrigin(t)
				id, err := engine.OpenStream(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				clientID, err := peer.OpenStream(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}, {Name: "x-large", Value: strings.Repeat("x", 1024)}}
				if err := peer.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: clientID, Headers: fields, EndStream: true}); err != nil {
					t.Fatal(err)
				}
				head, err := source.Receive(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				client := &observedHTTP2Server{http2Server: &http2Server{engine: source, identity: head.Identity, id: 1, head: &head}}
				var server ServerEndpoint = &http2Client{engine: engine, identity: id, id: 1}
				if test.lazy {
					server = &lazyServer{ready: make(chan struct{}), acquire: func(context.Context, *httpmsg.Request) (ServerEndpoint, error) {
						return &http2Client{engine: engine, identity: id, id: 1}, nil
					}}
				}
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				finished := make(chan struct{})
				go func() {
					defer close(finished)
					done <- (&streamDriver{stream: stream, client: client, server: server}).run(ctx)
				}()
				t.Cleanup(func() {
					cancel()
					await(t, finished)
				})
				await(t, entered)
				synctest.Wait()
				if err := manager.Do(t.Context(), func(context.Context) error {
					if !stream.flow.Intercepted() {
						t.Error("local send cleanup resumed intercepted error hook")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				siblingID, err := engine.OpenStream(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				sibling := &http2Client{engine: engine, identity: siblingID, id: 3}
				request, err := httpmsg.MakeRequest("GET", "https://example.com/", nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := sibling.Send(t.Context(), RequestHeaders{ID: 3, Request: request, EndStream: true}); err != nil {
					t.Fatal(err)
				}
				event, err := sibling.Receive(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if head, ok := event.(ResponseHeaders); !ok || head.Response.StatusCode != 204 {
					t.Fatalf("sibling response = %#v, want 204", event)
				}
				if err := manager.Do(t.Context(), func(context.Context) error {
					if !stream.flow.Intercepted() {
						t.Error("error hook resumed before sibling completed")
					}
					stream.flow.Resume()
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				response := make(chan h2.Event, 1)
				go func() {
					event, err := peer.ReceiveStream(t.Context(), clientID)
					if err != nil {
						t.Error(err)
					}
					response <- event
				}()
				headers := await(t, response)
				if headers.Kind != h2.Headers || len(headers.Headers) == 0 {
					t.Fatalf("driver response = %+v, want 502 HEADERS", headers)
				}
				if diff := gocmp.Diff(":status", headers.Headers[0].Name); diff != "" {
					t.Fatal(diff)
				}
				if diff := gocmp.Diff("502", headers.Headers[0].Value); diff != "" {
					t.Fatal(diff)
				}
				for !headers.EndStream {
					headers, err = peer.ReceiveStream(t.Context(), clientID)
					if err != nil {
						t.Fatal(err)
					}
					if headers.Receipt != nil {
						headers.Receipt.Complete()
					}
				}
				if err := await(t, done); err != nil {
					t.Fatal(err)
				}
				if client.failure == nil || client.failure.Code != GenericServerError {
					t.Fatalf("driver failure = %+v", client.failure)
				}
				if err := manager.Do(t.Context(), func(context.Context) error {
					if stream.flow.Intercepted() {
						t.Error("resumed error hook remained intercepted")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
