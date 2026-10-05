// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestHTTP1ConnectResponseMessageBoundary(t *testing.T) {
	tests := map[string]struct {
		response string
		want     []wireEvent
		tunnel   bool
	}{
		"success: established tunnel": {
			response: "HTTP/1.1 200 Connection established\r\n\r\ntunnel bytes",
			want: []wireEvent{
				{Kind: "response headers", ID: 1, Status: 200, End: true},
				{Kind: "response end", ID: 1},
				{Kind: "response data", ID: 1, Data: "tunnel bytes"},
			},
			tunnel: true,
		},
		"success: refused tunnel": {
			response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied",
			want: []wireEvent{
				{Kind: "response headers", ID: 1, Status: 403},
				{Kind: "response data", ID: 1, Data: "denied"},
				{Kind: "response end", ID: 1},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := layertest.Pipe(t)
			endpoint := newHTTP1Client(conn, newWireStore(), nil)
			if err := endpoint.Send(t.Context(), connectRequest()); err != nil {
				t.Fatal(err)
			}
			expectRead(t, peer, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
			if err := endpoint.Send(t.Context(), RequestEndOfMessage{ID: 1}); err != nil {
				t.Fatal(err)
			}
			write(t, peer, tt.response)
			if err := peer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			for i, want := range tt.want {
				event, err := endpoint.Receive(t.Context())
				if err != nil {
					t.Fatalf("event %d: %v", i, err)
				}
				if diff := gocmp.Diff(want, summarize(event)); diff != "" {
					t.Fatalf("event %d (-want +got):\n%s", i, diff)
				}
			}
			if event, err := endpoint.Receive(t.Context()); event != nil || !errors.Is(err, io.EOF) {
				t.Fatalf("after message and transport completion: %v, %v; want nil, EOF", event, err)
			}
			if tt.tunnel {
				if err := endpoint.Send(t.Context(), RequestData{ID: 1, Data: []byte("still writable")}); err != nil {
					t.Fatal(err)
				}
				expectRead(t, peer, "still writable")
			}
		})
	}
}

func TestLayerConnectRetryAfterRefusal(t *testing.T) {
	attempts := 0
	a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		if name == "http_connect" {
			attempts++
			if attempts == 1 {
				f.Response = &httpmsg.Response{HTTPVersion: "HTTP/1.1", StatusCode: 407, Reason: "Proxy Authentication Required", Headers: httpmsg.Headers{{Name: []byte("Content-Length"), Value: []byte("0")}}}
			}
		}
	}}
	s := newLayerSession(t, a, "connection_strategy=eager")
	child := &tunnelChild{received: make(chan []byte, 1)}
	s.c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) { return child, nil }
	s.start(hookdata.HTTPModeRegular)
	write(t, s.client, "CONNECT origin.test:443 HTTP/1.1\r\n\r\n")
	expectRead(t, s.client, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	write(t, s.client, "CONNECT origin.test:443 HTTP/1.1\r\n\r\nearly-bytes")
	expectRead(t, s.client, "HTTP/1.1 200 Connection established\r\n\r\n")
	if diff := gocmp.Diff([]byte("early-bytes"), await(t, child.received)); diff != "" {
		t.Fatal(diff)
	}
	expectRead(t, s.client, "early-bytes")
	origin := await(t, s.pool.origins)
	expectRead(t, origin, "origin-ping")
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"http_connect", "http_connect_error", "http_connect", "http_connected"}, a.calls); diff != "" {
		t.Fatal(diff)
	}
}

func TestHTTP1ConnectRequestMessageBoundary(t *testing.T) {
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)
	write(t, peer, "CONNECT example.com:443 HTTP/1.1\r\n\r\ntunnel bytes")
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	want := []wireEvent{
		{Kind: "request headers", ID: 1, Method: "CONNECT", End: true},
		{Kind: "request end", ID: 1},
	}
	for i, expected := range want {
		event, err := endpoint.Receive(t.Context())
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if diff := gocmp.Diff(expected, summarize(event)); diff != "" {
			t.Fatalf("event %d (-want +got):\n%s", i, diff)
		}
	}
	if err := endpoint.Send(t.Context(), ResponseHeaders{ID: 1, Response: mustResponse(t, 200, nil)}); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Send(t.Context(), ResponseEndOfMessage{ID: 1}); err != nil {
		t.Fatal(err)
	}
	expectRead(t, peer, response200)
	event, err := endpoint.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(wireEvent{Kind: "request data", ID: 1, Data: "tunnel bytes"}, summarize(event)); diff != "" {
		t.Fatalf("tunnel data (-want +got):\n%s", diff)
	}
	if event, err := endpoint.Receive(t.Context()); event != nil || !errors.Is(err, io.EOF) {
		t.Fatalf("after message and transport completion: %v, %v; want nil, EOF", event, err)
	}
	if err := endpoint.Send(t.Context(), ResponseData{ID: 1, Data: []byte("still writable")}); err != nil {
		t.Fatal(err)
	}
	expectRead(t, peer, "still writable")
}
