// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type observedHTTP2Server struct {
	*http2Server
	failure *ResponseProtocolError
}

func (s *observedHTTP2Server) Send(ctx context.Context, event ResponseEvent) error {
	if failure, ok := event.(ResponseProtocolError); ok {
		s.failure = &failure
	}
	return s.http2Server.Send(ctx, event)
}

func TestHTTP2InterceptTermination(t *testing.T) {
	hooks := map[string]struct{}{"requestheaders": {}, "request": {}, "responseheaders": {}, "response": {}}
	for hook := range hooks {
		t.Run(hook, func(t *testing.T) {
			tests := map[string]struct{ termination string }{
				"success: normal END_STREAM resumes":      {termination: "complete"},
				"error: reset releases interception":      {termination: "reset"},
				"error: disconnect releases interception": {termination: "disconnect"},
			}
			for name, test := range tests {
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()
					entered := make(chan struct{})
					a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
						if name == hook {
							f.Intercept()
							close(entered)
						}
					}}
					s, m := newTestStream(t, a)
					wire, transport := net.Pipe()
					peer, err := h2.New(wire, h2.Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "peer"}})
					if err != nil {
						t.Fatal(err)
					}
					source, err := h2.New(transport, h2.Config{Descriptor: layer.EndpointDescriptor{Identity: "source"}})
					if err != nil {
						t.Fatal(err)
					}
					var workers sync.WaitGroup
					workers.Go(func() { _ = peer.Run(ctx); _ = wire.Close() })
					workers.Go(func() { _ = source.Run(ctx); _ = transport.Close() })
					defer func() { cancel(); workers.Wait() }()
					destination, origin := h2EndpointPair(t)
					id, err := peer.OpenStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					sid, err := destination.OpenStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}}
					if err := peer.Send(ctx, h2.Event{Kind: h2.Headers, Identity: id, Headers: fields, EndStream: true}); err != nil {
						t.Fatal(err)
					}
					head, err := source.Receive(ctx)
					if err != nil {
						t.Fatal(err)
					}
					client := &observedHTTP2Server{http2Server: &http2Server{engine: source, failureDone: source.StreamFailed(head.Identity), identity: head.Identity, id: 1, head: &head}}
					server := &http2Client{engine: destination, failureDone: destination.StreamFailed(sid), identity: sid, id: 1}
					done := make(chan error, 1)
					go func() { done <- (&streamDriver{stream: s, client: client, server: server}).run(ctx) }()
					if strings.HasPrefix(hook, "response") {
						request, err := origin.Receive(ctx)
						if err != nil {
							t.Fatal(err)
						}
						if err := origin.Send(ctx, h2.Event{Kind: h2.Headers, Identity: request.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "204"}}, EndStream: true}); err != nil {
							t.Fatal(err)
						}
					}
					select {
					case <-entered:
					case <-ctx.Done():
						t.Fatal("hook did not intercept")
					}
					if test.termination == "complete" {
						if strings.HasPrefix(hook, "response") {
							<-destination.StreamDone(sid)
						}
						if err := m.Do(ctx, func(context.Context) error {
							if !s.flow.Intercepted() {
								t.Error("normal completion released intercepted hook")
							}
							s.flow.Resume()
							return nil
						}); err != nil {
							t.Fatal(err)
						}
						if strings.HasPrefix(hook, "request") {
							request, err := origin.Receive(ctx)
							if err != nil {
								t.Fatal(err)
							}
							if err := origin.Send(ctx, h2.Event{Kind: h2.Headers, Identity: request.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "204"}}, EndStream: true}); err != nil {
								t.Fatal(err)
							}
						}
						response, err := peer.ReceiveStream(ctx, id)
						if err != nil || response.Kind != h2.Headers || !response.EndStream {
							t.Fatalf("response = %+v, %v", response, err)
						}
					} else if test.termination == "reset" {
						if err := peer.CancelStream(id, http2.ErrCodeCancel); err != nil {
							t.Fatal(err)
						}
					} else if err := wire.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						if err != nil {
							t.Fatalf("exchange exited without recording protocol failure: %v", err)
						}
					case <-ctx.Done():
						t.Fatal("intercepted exchange did not finish")
					}
					if test.termination == "complete" {
						if diff := gocmp.Diff([]string{"requestheaders", "request", "responseheaders", "response"}, a.calls); diff != "" {
							t.Fatal(diff)
						}
					} else if err := m.Do(ctx, func(context.Context) error {
						wantCode := ClientDisconnected
						if test.termination == "reset" {
							wantCode = Cancel
						}
						if client.failure == nil {
							t.Error("exchange did not emit its protocol failure")
						} else {
							if diff := gocmp.Diff(wantCode, client.failure.Code); diff != "" {
								t.Error(diff)
							}
							if test.termination == "reset" && !strings.Contains(client.failure.Message, "CANCEL") {
								t.Errorf("reset lost its typed code: %+v", client.failure)
							}
							if client.failure.Message == "EOF" {
								t.Error("failure collapsed to EOF")
							}
						}
						if s.flow.Intercepted() {
							t.Error("failed exchange remains intercepted")
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}
