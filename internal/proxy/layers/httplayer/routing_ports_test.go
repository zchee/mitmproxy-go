// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestLayerConnectHTTPMatrix(t *testing.T) {
	tests := map[string]struct {
		strategy string
		host     bool
	}{
		"success: eager with host":    {"eager", true},
		"success: eager without host": {"eager", false},
		"success: lazy with host":     {"lazy", true},
		"success: lazy without host":  {"lazy", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLayerSession(t, nil, "connection_strategy="+tt.strategy)
			s.c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
				return &httpLayer{route: routeConfig{mode: modeTransparent}}, nil
			}
			s.start(hookdata.HTTPModeRegular)
			head := "CONNECT example.proxy:80 HTTP/1.1\r\n"
			if tt.host {
				head += "Host: example.com:80\r\n"
			}
			write(t, s.client, head+"\r\n")
			expectRead(t, s.client, "HTTP/1.1 200 Connection established\r\n\r\n")
			write(t, s.client, "GET /foo?hello=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
			origin := await(t, s.pool.origins)
			expectRead(t, origin, "GET /foo?hello=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
			write(t, origin, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
			expectRead(t, s.client, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
			finishLayerSession(t, s, []string{"http_connect", "http_connected", "requestheaders", "request", "responseheaders", "response"})
			if s.pool.openCount() != 1 {
				t.Fatal("CONNECT and HTTP request opened separate origins")
			}
		})
	}
}

func TestLayerRejectProxyChain(t *testing.T) {
	tests := map[string]struct{ strategy string }{
		"error: eager nested CONNECT": {"eager"},
		"error: lazy nested CONNECT":  {"lazy"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLayerSession(t, nil, "connection_strategy="+tt.strategy)
			s.c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
				return &httpLayer{route: routeConfig{mode: modeTransparent}}, nil
			}
			s.start(hookdata.HTTPModeRegular)
			write(t, s.client, "CONNECT proxy:8080 HTTP/1.1\r\nHost: proxy:8080\r\n\r\n")
			expectRead(t, s.client, "HTTP/1.1 200 Connection established\r\n\r\n")
			write(t, s.client, "CONNECT second-proxy:8080 HTTP/1.1\r\nHost: proxy:8080\r\n\r\n")
			data, err := io.ReadAll(s.client)
			if err != nil || !bytes.Contains(data, []byte("mitmproxy received an HTTP CONNECT request even though it is not running in regular/upstream mode.")) {
				t.Fatalf("nested CONNECT response = (%q, %v)", data, err)
			}
			if err := await(t, s.done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLayerConnectionCloseMatrix(t *testing.T) {
	tests := map[string]struct{ client, server bool }{
		"success: client asks to close": {client: true},
		"success: server asks to close": {server: true},
		"success: both ask to close":    {client: true, server: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLayerSession(t, nil)
			s.start(hookdata.HTTPModeRegular)
			request, response := "Host: example\r\n", "Content-Length: 0\r\n"
			if tt.client {
				request += "Connection: close\r\n"
			}
			if tt.server {
				response += "Connection: close\r\n"
			}
			write(t, s.client, "GET http://example/ HTTP/1.1\r\n"+request+"\r\n")
			origin := await(t, s.pool.origins)
			expectRead(t, origin, "GET / HTTP/1.1\r\n"+request+"\r\n")
			write(t, origin, "HTTP/1.1 200 OK\r\n"+response+"\r\n")
			data, err := io.ReadAll(s.client)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("HTTP/1.1 200 OK\r\n"+response+"\r\n", string(data)); diff != "" {
				t.Fatal(diff)
			}
			if data, err := io.ReadAll(origin); err != nil || len(data) != 0 {
				t.Fatalf("origin closure = (%q, %v)", data, err)
			}
			if err := await(t, s.done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLayerExpectContinueWire(t *testing.T) {
	s := newLayerSession(t, nil)
	s.start(hookdata.HTTPModeRegular)
	write(t, s.client, "PUT http://example.com/large-file HTTP/1.1\r\nHost: example.com\r\nContent-Length: 15\r\nExpect: 100-continue\r\n\r\n")
	expectRead(t, s.client, "HTTP/1.1 100 Continue\r\n\r\n")
	write(t, s.client, "lots of content")
	origin := await(t, s.pool.origins)
	expectRead(t, origin, "PUT /large-file HTTP/1.1\r\nHost: example.com\r\nContent-Length: 15\r\n\r\nlots of content")
	write(t, origin, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	expectRead(t, s.client, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	finishLayerSession(t, s, []string{"requestheaders", "request", "responseheaders", "response"})
}

func TestLayerSNISelection(t *testing.T) {
	tests := map[string]struct{ client, server, want string }{
		"success: transparent destination preserves client SNI": {client: "example.com", want: "example.com"},
		"success: reverse destination preserves configured SNI": {client: "localhost", server: "example.local", want: "example.local"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pool, peers, _ := newUpstreamPoolSession(t)
			c := pool.c
			var f *flow.HTTPFlow
			if err := c.Do(t.Context(), func(context.Context) error {
				c.Data.Client.SNI = new(tt.client)
				c.Data.Server = connection.NewServer(&connection.Address{Host: "192.0.2.42", Port: 443})
				c.Data.Server.TLS = true
				if tt.server != "" {
					c.Data.Server.SNI = new(tt.server)
				}
				f = flow.NewHTTPFlow(c.Data.Client, c.Data.Server, true)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			request := &httpmsg.Request{Method: "GET", Scheme: "https", Host: "192.0.2.42", Port: 443, Path: "/", HTTPVersion: "HTTP/1.1"}
			l := &httpLayer{route: routeConfig{mode: modeTransparent}}
			endpoint, err := l.connect(t.Context(), c, &httpStream{flow: f}, request, newWireStore(), make(map[layer.Conn]*http1Client), nil)
			if err != nil {
				t.Fatal(err)
			}
			peer := await(t, peers)
			if err := c.Do(t.Context(), func(context.Context) error {
				if c.Data.Server.SNI == nil || *c.Data.Server.SNI != tt.want {
					t.Errorf("selected SNI = %v, want %q", c.Data.Server.SNI, tt.want)
				}
				if diff := gocmp.Diff(connection.Address{Host: "192.0.2.42", Port: 443}, *c.Data.Server.Address); diff != "" {
					t.Error(diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := endpoint.Send(t.Context(), RequestHeaders{ID: 1, Request: request, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			expectRead(t, peer, "GET / HTTP/1.1\r\n\r\n")
		})
	}
}

func TestLayerInheritedServerError(t *testing.T) {
	pool, peers, _ := newUpstreamPoolSession(t)
	s := newLayerSession(t, nil)
	s.c.Pool = pool.base
	s.c.Data.Server = connection.NewServer(&connection.Address{Host: "example.com", Port: 443})
	s.c.Data.Server.Error = new("tls verify failed")
	s.start(hookdata.HTTPModeTransparent)
	write(t, s.client, "GET / HTTP/1.1\r\n\r\n")
	data, err := io.ReadAll(s.client)
	if err != nil || !bytes.Contains(data, []byte("502 Bad Gateway")) || !bytes.Contains(data, []byte("tls verify failed")) {
		t.Fatalf("inherited error response = (%q, %v)", data, err)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peers:
		t.Fatal("preexisting origin error triggered another dial")
	default:
	}
}

func TestStreamAdditionalKillHooks(t *testing.T) {
	tests := map[string]struct {
		synthetic bool
		hooks     []string
	}{
		"error: kill synthetic response headers": {true, []string{"requestheaders", "request", "responseheaders", "error"}},
		"error: kill in error hook":              {false, []string{"requestheaders", "request", "responseheaders", "error"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if tt.synthetic && name == "request" {
					f.Response = &httpmsg.Response{HTTPVersion: "HTTP/1.1", StatusCode: 200}
				}
				if tt.synthetic && name == "responseheaders" || !tt.synthetic && name == "error" {
					if err := f.Kill(); err != nil {
						t.Error(err)
					}
				}
			}}
			s, _ := newTestStream(t, a)
			drainStream(t, s, requestHead("0"))
			events := drainStream(t, s, RequestEndOfMessage{ID: 1})
			if !tt.synthetic {
				drainStream(t, s, responseHead("12"))
				events = drainStream(t, s, ResponseProtocolError{ID: 1, Code: GenericServerError, Message: "peer closed connection"})
			}
			if len(events) == 0 || events[0].(ResponseProtocolError).Code != Kill {
				t.Fatalf("kill output = %+v", events)
			}
			if diff := gocmp.Diff(tt.hooks, a.calls); diff != "" {
				t.Fatal(diff)
			}
			if !s.done() || s.snapshot.Live || !strings.Contains(s.snapshot.Error.Msg, "killed") {
				t.Fatalf("killed flow = %+v", s.snapshot)
			}
		})
	}
}
