// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

// Upstream next_layer._setup_explicit_http_proxy keeps regular HTTP routing
// underneath client TLS; the absolute URI still chooses the origin.
func TestSecureProxyAbsoluteForm(t *testing.T) {
	requests := make(chan string, 1)
	origin := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- request.Method + " " + request.RequestURI + " " + request.Proto + "\r\nHost: " + request.Host + "\r\n"
		_, _ = io.WriteString(w, "absolute-form reply")
	}))
	closed := &connectionFinished{done: make(chan struct{})}
	p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin), proxytest.WithAddons(closed))
	client := tls.Client(dial(t, p.Addr), &tls.Config{
		RootCAs: p.CAPool, ServerName: "proxy.test", NextProtos: []string{"http/1.1"},
	})
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff("http/1.1", client.ConnectionState().NegotiatedProtocol); diff != "" {
		t.Fatalf("secure proxy ALPN (-want +got):\n%s", diff)
	}
	response, body := httpExchange(t, client, "GET http://example.test/absolute?query=value HTTP/1.1\r\nHost: example.test\r\n\r\n")
	if response.StatusCode != http.StatusOK || string(body) != "absolute-form reply" {
		t.Fatalf("absolute-form response = %d %q", response.StatusCode, body)
	}
	if diff := gocmp.Diff("GET /absolute?query=value HTTP/1.1\r\nHost: example.test\r\n", receive(t, requests)); diff != "" {
		t.Fatalf("origin request (-want origin-form +got):\n%s", diff)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	receive(t, closed.done)
	hooks := p.Recorder.Hooks()
	for _, hook := range []string{"tls_established_client", "requestheaders", "request", "response"} {
		if !slices.Contains(hooks, hook) {
			t.Errorf("missing %s hook; got %v", hook, hooks)
		}
	}
	if slices.Contains(hooks, "http_connect") {
		t.Fatalf("absolute-form request unexpectedly used CONNECT: %v", hooks)
	}
}

// Upstream next_layer._setup_reverse_proxy fixes the child to TCPLayer for
// raw reverse modes, even when the decrypted client bytes resemble HTTP.
func TestReverseRawTLSClientHTTPBytes(t *testing.T) {
	tests := map[string]struct{ scheme string }{
		"success: TLS origin":       {scheme: "tls"},
		"success: plaintext origin": {scheme: "tcp"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var origin *proxytest.Origin
			if tt.scheme == "tls" {
				origin = proxytest.StartTLSOrigin(t, []string{"example.test"}, nil)
			} else {
				origin = proxytest.StartEchoOrigin(t)
			}
			closed := &connectionFinished{done: make(chan struct{})}
			p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin), proxytest.WithAddons(closed),
				proxytest.WithOptions(map[string]any{"mode": []string{"reverse:" + tt.scheme + "://example.test:443"}}))
			client := tls.Client(dial(t, p.Addr), &tls.Config{RootCAs: p.CAPool, ServerName: "example.test"})
			if err := client.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			// A raw origin echoes the request bytes, not an HTTP response. Keeping
			// an absolute URI here also detects accidental HTTP target routing.
			exchange(t, client, "GET http://unmapped.test/raw HTTP/1.1\r\nHost: unmapped.test\r\n\r\n")
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			receive(t, closed.done)
			hooks := p.Recorder.Hooks()
			for _, hook := range []string{"tls_established_client", "tcp_start", "tcp_message", "tcp_end"} {
				if !slices.Contains(hooks, hook) {
					t.Errorf("missing %s hook; got %v", hook, hooks)
				}
			}
			for _, hook := range []string{"requestheaders", "request", "responseheaders", "response", "http_connect", "error"} {
				if slices.Contains(hooks, hook) {
					t.Errorf("raw reverse mode dispatched HTTP hook %s; got %v", hook, hooks)
				}
			}
		})
	}
}

type connectionFinished struct{ done chan struct{} }

// ClientDisconnected signals that the observed client connection has finished.
func (c *connectionFinished) ClientDisconnected(context.Context, *connection.Client) error {
	close(c.done)
	return nil
}
