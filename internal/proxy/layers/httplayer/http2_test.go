// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func h2EndpointPair(t *testing.T) (*h2.Endpoint, *h2.Endpoint) {
	t.Helper()
	a, b := net.Pipe()
	deadline := time.Now().Add(30 * time.Second)
	if err := a.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := b.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	client, err := h2.New(a, h2.Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "client"}, ValidateInboundHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	server, err := h2.New(b, h2.Config{Descriptor: layer.EndpointDescriptor{Identity: "server"}, ValidateInboundHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	workers.Go(func() { _ = client.Run(ctx); _ = a.Close() })
	workers.Go(func() { _ = server.Run(ctx); _ = b.Close() })
	t.Cleanup(func() { cancel(); workers.Wait() })
	return client, server
}

func TestHTTP2ClientEvents(t *testing.T) {
	t.Parallel()
	client, peer := h2EndpointPair(t)
	identity, err := client.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &http2Client{engine: client, identity: identity, id: 42, normalize: true}
	request, err := httpmsg.MakeRequest("GET", "https://example.com/", nil, httpmsg.Headers{{Name: []byte("X-Test"), Value: []byte("one")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Send(t.Context(), RequestHeaders{ID: 42, Request: request, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Send(t.Context(), RequestEndOfMessage{ID: 42}); err != nil {
		t.Fatal(err)
	}
	head, err := peer.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if head.Identity.Stream != identity.Stream || !head.EndStream {
		t.Fatalf("wire request = %+v", head)
	}
	if err := peer.Send(t.Context(), h2.Event{Kind: h2.Informational, Identity: head.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "103"}}}); err != nil {
		t.Fatal(err)
	}
	if err := peer.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: head.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "x-test", Value: "one"}, {Name: "x-test", Value: "two"}}}); err != nil {
		t.Fatal(err)
	}
	event, err := endpoint.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	headers, ok := event.(ResponseHeaders)
	if !ok || headers.ID != 42 || headers.Response.HTTPVersion != "HTTP/2.0" || headers.Response.StatusCode != 200 {
		t.Fatalf("response head = %#v", event)
	}
	if diff := gocmp.Diff([]string{"one", "two"}, headers.Response.Headers.GetAll("x-test")); diff != "" {
		t.Errorf("ordered duplicate fields (-want +got):\n%s", diff)
	}
	if err := peer.Send(t.Context(), h2.Event{Kind: h2.Data, Identity: head.Identity, Data: []byte("body")}); err != nil {
		t.Fatal(err)
	}
	event, err = endpoint.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	data, ok := event.(ResponseData)
	if !ok || string(data.Data) != "body" || data.ID != 42 {
		t.Fatalf("response data = %#v", event)
	}
	receipt := endpoint.takeReceipt()
	if receipt == nil || receipt.OriginalBytes() != 4 || !receipt.Complete() {
		t.Fatal("original DATA receipt was not transferred to the owner")
	}
	if err := peer.Send(t.Context(), h2.Event{Kind: h2.Trailers, Identity: head.Identity, Headers: []hpack.HeaderField{{Name: "x-trailer", Value: "last"}}, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	event, err = endpoint.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if trailers, ok := event.(ResponseTrailers); !ok || trailers.Trailers.Get("x-trailer") != "last" {
		t.Fatalf("response trailers = %#v", event)
	}
	event, err = endpoint.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := event.(ResponseEndOfMessage); !ok {
		t.Fatalf("response end = %#v", event)
	}
}

func TestHTTP2ServerEvents(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		body bool
	}{
		"success: HEADERS end stream produces one HTTP end":   {},
		"success: DATA end stream keeps its original receipt": {body: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			peer, server := h2EndpointPair(t)
			identity, err := peer.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			fields := []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}}
			if err := peer.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: identity, Headers: fields, EndStream: !tt.body}); err != nil {
				t.Fatal(err)
			}
			head, err := server.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &http2Server{engine: server, identity: head.Identity, id: 99, normalize: true, head: &head}
			event, err := endpoint.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if headers, ok := event.(RequestHeaders); !ok || headers.ID != 99 || headers.Request.Host != "example.com" {
				t.Fatalf("request head = %#v", event)
			}
			if tt.body {
				if err := peer.Send(t.Context(), h2.Event{Kind: h2.Data, Identity: identity, Data: []byte("body"), EndStream: true}); err != nil {
					t.Fatal(err)
				}
				event, err = endpoint.Receive(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if data, ok := event.(RequestData); !ok || string(data.Data) != "body" {
					t.Fatalf("request data = %#v", event)
				}
				receipt := endpoint.takeReceipt()
				if receipt == nil || !receipt.Complete() {
					t.Fatal("request receipt missing or already settled")
				}
			}
			event, err = endpoint.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := event.(RequestEndOfMessage); !ok {
				t.Fatalf("request end = %#v", event)
			}
			response := &httpmsg.Response{HTTPVersion: "HTTP/2.0", StatusCode: 204}
			if err := endpoint.Send(t.Context(), ResponseHeaders{ID: 99, Response: response, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			if err := endpoint.Send(t.Context(), ResponseEndOfMessage{ID: 99}); err != nil {
				t.Fatal(err)
			}
			wire, err := peer.ReceiveStream(t.Context(), identity)
			if err != nil || wire.Kind != h2.Headers || !wire.EndStream {
				t.Fatalf("response wire = %+v, error = %v", wire, err)
			}
		})
	}
}

func TestHTTP2ResetCode(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		code ErrorCode
		want http2.ErrCode
	}{
		"success: cancel":            {code: Cancel, want: http2.ErrCodeCancel},
		"success: client disconnect": {code: ClientDisconnected, want: http2.ErrCodeCancel},
		"success: passthrough close": {code: PassthroughClose, want: http2.ErrCodeCancel},
		"success: retry using http1": {code: HTTP11Required, want: http2.ErrCodeHTTP11Required},
		"success: kill":              {code: Kill, want: http2.ErrCodeInternal},
		"success: malformed request": {code: GenericClientError, want: http2.ErrCodeInternal},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, h2ResetCode(tt.code)); diff != "" {
				t.Errorf("reset code (-want +got):\n%s", diff)
			}
		})
	}
}
