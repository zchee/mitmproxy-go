// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

// clientSignal reports each client connection without blocking the hook.
type clientSignal struct{ connected chan struct{} }

func (c *clientSignal) ClientConnected(context.Context, *connection.Client) error {
	select {
	case c.connected <- struct{}{}:
	default:
	}
	return nil
}

// TestHTTPSelfConnectAddressForms sends a request for the proxy's own wildcard
// listener spelled as other forms of a loopback address. The proxy must refuse
// it instead of connecting to itself, where the request would be forwarded to
// itself again without end.
func TestHTTPSelfConnectAddressForms(t *testing.T) {
	const refused = "Request destination unknown. Unable to figure out where this request should be forwarded to."
	tests := map[string]struct {
		host         string
		listenHost   string
		resolvedHost string
	}{
		"error: IPv4-mapped IPv6 loopback":        {host: "::ffff:127.0.0.1"},
		"error: uncompressed IPv6 loopback":       {host: "0:0:0:0:0:0:0:1"},
		"error: IPv4 loopback":                    {host: "127.0.0.1"},
		"error: resolved IPv4, wildcard listener": {host: "self.test", resolvedHost: "127.0.0.1"},
		"error: resolved IPv6, wildcard listener": {host: "self.test", resolvedHost: "::1"},
		"error: resolved IPv4, loopback listener": {host: "self.test", listenHost: "127.0.0.1", resolvedHost: "127.0.0.1"},
		"error: resolved IPv6, loopback listener": {host: "self.test", listenHost: "127.0.0.1", resolvedHost: "::1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			signal := &clientSignal{connected: make(chan struct{}, 2)}
			origin := &proxytest.Origin{}
			opts := []proxytest.Option{proxytest.WithOptions(map[string]any{"listen_host": tt.listenHost}), proxytest.WithAddons(signal)}
			if tt.resolvedHost != "" {
				opts = append(opts, proxytest.WithOrigin(tt.host, origin))
			}
			p := proxytest.Start(t, opts...)
			_, port, err := net.SplitHostPort(p.Addr)
			if err != nil {
				t.Fatal(err)
			}
			origin.Addr = net.JoinHostPort(tt.resolvedHost, port)
			conn := dial(t, net.JoinHostPort("127.0.0.1", port))
			target := net.JoinHostPort(tt.host, port)
			if _, err := io.WriteString(conn, "GET http://"+target+"/ HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			type result struct {
				status int
				body   string
				err    error
			}
			done := make(chan result, 1)
			go func() {
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					done <- result{err: err}
					return
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				done <- result{status: response.StatusCode, body: string(body), err: err}
			}()
			hang := time.After(30 * time.Second)
			select {
			case <-signal.connected:
			case <-hang:
				t.Fatal("the test client never connected")
			}
			var got result
			select {
			case got = <-done:
			case <-signal.connected:
				t.Fatalf("a second client connected: the request for %s looped into the proxy", target)
			case <-hang:
				t.Fatal("no response to the self-targeted request")
			}
			if got.err != nil || got.status != http.StatusBadGateway || !strings.Contains(got.body, refused) {
				t.Fatalf("response = %d %q (%v), want 502 with %q", got.status, got.body, got.err, refused)
			}
			// Settle the hook record behind the dispatch barrier before counting.
			if err := p.Master.Do(t.Context(), func(context.Context) error {
				failures := 0
				for _, call := range p.Recorder.Calls() {
					if call.Hook == "server_connect_error" {
						failures++
						server := call.Arg.(*hookdata.ServerConnection).Server
						if diff := gocmp.Diff(new(refused), server.Error); diff != "" {
							t.Errorf("server.Error (-want +got):\n%s", diff)
						}
					}
				}
				if failures != 1 {
					t.Errorf("server_connect_error fired %d times, want 1", failures)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			clients := 0
			for _, hook := range p.Recorder.Hooks() {
				switch hook {
				case "client_connected":
					clients++
				case "server_connected":
					t.Fatal("a server connection was opened")
				}
			}
			if clients != 1 {
				t.Fatalf("client_connected fired %d times, want 1", clients)
			}
		})
	}
}
