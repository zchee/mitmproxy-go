// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/options"
)

func (a *streamAddon) HTTPConnect(_ context.Context, f *flow.HTTPFlow) error {
	return a.record("http_connect", f)
}

func (a *streamAddon) HTTPConnected(_ context.Context, f *flow.HTTPFlow) error {
	return a.record("http_connected", f)
}

func (a *streamAddon) HTTPConnectError(_ context.Context, f *flow.HTTPFlow) error {
	return a.record("http_connect_error", f)
}

// fakePool implements layer.ServerPool for CONNECT tests.
type fakePool struct {
	opens atomic.Int64
	err   error
}

func (p *fakePool) Open(_ context.Context, srv *connection.Server, _ layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	p.opens.Add(1)
	if p.err != nil {
		return nil, nil, p.err
	}
	return nil, srv, nil
}

func (p *fakePool) Upgrade(_ context.Context, srv *connection.Server, _ func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) (layer.Conn, *connection.Server, error) {
	return nil, srv, nil
}

func (*fakePool) Lookup(*connection.Server) (layer.Conn, bool) { return nil, false }

func connectRequest() RequestHeaders {
	return RequestHeaders{ID: 1, EndStream: true, Request: &httpmsg.Request{
		HTTPVersion: "HTTP/1.1", Method: "CONNECT",
		Host: "example.com", Port: 443, Authority: "example.com:443",
	}}
}

func registerConnectionStrategy(t *testing.T, s *httpStream, strategy string) {
	t.Helper()
	if err := s.c.Data.Options.Add(t.Context(), "connection_strategy", options.TypeStr,
		"eager",
		"Determine when server connections should be established. When set to lazy, mitmproxy "+
			"tries to defer establishing an upstream connection as long as possible. This makes it possible to "+
			"use server replay while being offline. When set to eager, mitmproxy can detect protocols with "+
			"server-side greetings, as well as accurately mirror TLS ALPN negotiation.",
		options.WithChoices("eager", "lazy")); err != nil {
		t.Fatal(err)
	}
	if err := s.c.Data.Options.Set(t.Context(), "connection_strategy="+strategy); err != nil {
		t.Fatal(err)
	}
}

func TestStreamConnect(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		strategy    string
		dialErr     error
		edit        func(string, *flow.HTTPFlow)
		wantEvents  []wireEvent
		wantHooks   []string
		wantOpens   int64
		established bool
	}{
		"success: tunnel established lazily": {
			strategy: "lazy",
			wantEvents: []wireEvent{
				{Kind: "response headers", ID: 1, Status: 200, End: true},
				{Kind: "response end", ID: 1},
			},
			wantHooks:   []string{"http_connect", "http_connected"},
			established: true,
		},
		"success: eager strategy proves the destination": {
			strategy: "eager",
			wantEvents: []wireEvent{
				{Kind: "response headers", ID: 1, Status: 200, End: true},
				{Kind: "response end", ID: 1},
			},
			wantHooks:   []string{"http_connect", "http_connected"},
			wantOpens:   1,
			established: true,
		},
		"success: eager connect failure yields 502": {
			strategy: "eager",
			dialErr:  errors.New("connection refused"),
			wantEvents: []wireEvent{
				{Kind: "response headers", ID: 1, Status: 502},
				{Kind: "response data", ID: 1, Data: "Cannot connect to example.com:443: connection refused " +
					"If you plan to redirect requests away from this server, " +
					"consider setting `connection_strategy` to `lazy` to suppress early connections."},
				{Kind: "response end", ID: 1},
			},
			wantHooks: []string{"http_connect", "http_connect_error"},
			wantOpens: 1,
		},
		"success: handler refusal skips the connection": {
			strategy: "eager",
			edit: func(name string, f *flow.HTTPFlow) {
				if name != "http_connect" {
					return
				}
				f.Response = &httpmsg.Response{
					HTTPVersion: "HTTP/1.1", StatusCode: 403, Reason: "Forbidden", RawContent: []byte{},
				}
			},
			wantEvents: []wireEvent{
				{Kind: "response headers", ID: 1, Status: 403, End: true},
				{Kind: "response end", ID: 1},
			},
			wantHooks: []string{"http_connect", "http_connect_error"},
		},
		"success: killed connect answers with no hooks or response": {
			strategy: "lazy",
			edit: func(name string, f *flow.HTTPFlow) {
				if name != "http_connect" {
					return
				}
				if err := f.Kill(); err != nil {
					panic(err)
				}
			},
			wantEvents: []wireEvent{
				{Kind: "response error", ID: 1, Code: Kill, Message: "killed"},
			},
			wantHooks: []string{"http_connect"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := &streamAddon{edit: tt.edit}
			s, _ := newTestStream(t, a)
			registerConnectionStrategy(t, s, tt.strategy)
			pool := &fakePool{err: tt.dialErr}
			s.c.Pool = pool

			got := make([]wireEvent, 0, len(tt.wantEvents))
			for _, event := range drainStream(t, s, connectRequest()) {
				got = append(got, summarize(event))
			}
			if diff := gocmp.Diff(tt.wantEvents, got); diff != "" {
				t.Fatalf("events differ (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantHooks, a.calls); diff != "" {
				t.Fatalf("hooks differ (-want +got):\n%s", diff)
			}
			if got := pool.opens.Load(); got != tt.wantOpens {
				t.Fatalf("pool opens = %d, want %d", got, tt.wantOpens)
			}
			if s.connectEstablished != tt.established {
				t.Fatalf("connectEstablished = %t, want %t", s.connectEstablished, tt.established)
			}
			if tt.established {
				if !s.done() || s.failed {
					t.Fatalf("established tunnel: done = %t, failed = %t", s.done(), s.failed)
				}
				if s.c.Data.Server.Address == nil || s.c.Data.Server.Address.Host != "example.com" || s.c.Data.Server.Address.Port != 443 {
					t.Fatalf("server address = %v, want example.com:443", s.c.Data.Server.Address)
				}
			} else if !s.failed {
				t.Fatal("refused tunnel did not fail the stream")
			}
		})
	}
}

func TestStreamRequestValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		route      routeConfig
		request    RequestHeaders
		wantEvents []wireEvent
		wantHooks  []string
	}{
		"error: ambiguous framing refused before any forwarding": {
			route: routeConfig{mode: modeRegular, validateInboundHeaders: true},
			request: RequestHeaders{ID: 1, Request: &httpmsg.Request{
				HTTPVersion: "HTTP/1.1", Method: "POST", Scheme: "http",
				Host: "example.com", Port: 80, Path: "/",
				Headers: httpmsg.Headers{
					{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")},
					{Name: []byte("Content-Length"), Value: []byte("3")},
				},
			}},
			wantEvents: []wireEvent{{
				Kind: "response error", ID: 1, Code: RequestValidationFailed,
				Message: "Received message with both transfer-encoding and content-length headers from client, " +
					"refusing to prevent request smuggling attacks. " +
					"Disable the validate_inbound_headers option to skip this security check.",
			}},
			wantHooks: []string{"requestheaders", "error"},
		},
		"error: unknown destination refused without hooks": {
			route: routeConfig{mode: modeRegular},
			request: RequestHeaders{ID: 1, Request: &httpmsg.Request{
				HTTPVersion: "HTTP/1.1", Method: "GET", Path: "/x",
			}},
			wantEvents: []wireEvent{{
				Kind: "response error", ID: 1, Code: DestinationUnknown,
				Message: "HTTP request has no host header, destination unknown.",
			}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := &streamAddon{}
			s, _ := newTestStream(t, a)
			s.route = tt.route

			got := make([]wireEvent, 0, len(tt.wantEvents))
			for _, event := range drainStream(t, s, tt.request) {
				got = append(got, summarize(event))
			}
			if diff := gocmp.Diff(tt.wantEvents, got); diff != "" {
				t.Fatalf("events differ (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantHooks, a.calls); diff != "" {
				t.Fatalf("hooks differ (-want +got):\n%s", diff)
			}
			if !s.failed {
				t.Fatal("refused request did not fail the stream")
			}
		})
	}
}
