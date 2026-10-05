// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/options"
)

type upstreamConnectAddon struct {
	request chan *flow.HTTPFlow
}

func (*upstreamConnectAddon) Name() string { return "upstream-connect-observer" }

func (a *upstreamConnectAddon) HTTPConnectUpstream(_ context.Context, f *flow.HTTPFlow) error {
	f.Request.Headers.Set("X-Connect-Hook", "applied")
	a.request <- f
	return nil
}

func TestUpstreamConnectHandshake(t *testing.T) {
	tests := map[string]struct {
		host     string
		head     string
		response string
		noHost   bool
		wantErr  string
	}{
		"success: hostname and buffered bytes": {
			host: "origin.test", head: "origin.test:443",
			response: "HTTP/1.1 200 Connection established\r\n\r\ntunnel greeting",
		},
		"success: IPv6 authority": {
			host: "::1", head: "[::1]:443",
			response: "HTTP/1.1 200 Connection established\r\n\r\ntunnel greeting",
		},
		"success: IDNA authority": {
			host: "bücher.test", head: "xn--bcher-kva.test:443",
			response: "HTTP/1.1 200 Connection established\r\n\r\ntunnel greeting",
		},
		"success: optional Host and non-200 success": {
			host: "origin.test", head: "origin.test:443", noHost: true,
			response: "HTTP/1.1 204 No Content\r\n\r\ntunnel greeting",
		},
		"error: upstream refusal": {
			host: "origin.test", head: "origin.test:443",
			response: "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
			wantErr:  "Upstream proxy proxy.test:3128 refused HTTP CONNECT request: 407 Proxy Authentication Required",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLayerSession(t, nil)
			if err := s.m.Options.Add(t.Context(), "http_connect_send_host_header", options.TypeBool, !tt.noHost, "Send a Host header in CONNECT requests."); err != nil {
				t.Fatal(err)
			}
			a := &upstreamConnectAddon{request: make(chan *flow.HTTPFlow, 1)}
			if err := s.m.Addons.Add(t.Context(), a); err != nil {
				t.Fatal(err)
			}
			conn, peer := layertest.Pipe(t)
			pool := &upstreamPool{c: s.c}
			proxy := connection.NewServer(&connection.Address{Host: "proxy.test", Port: 3128})
			type result struct {
				conn layer.Conn
				err  error
			}
			done := make(chan result, 1)
			go func() {
				conn, err := pool.establishTunnel(t.Context(), conn, proxy, connection.Address{Host: tt.host, Port: 443})
				done <- result{conn: conn, err: err}
			}()
			head := "CONNECT " + tt.head + " HTTP/1.1\r\n"
			if !tt.noHost {
				head += "Host: " + tt.head + "\r\n"
			}
			head += "X-Connect-Hook: applied\r\n\r\n"
			expectRead(t, peer, head)
			write(t, peer, tt.response)
			got := await(t, done)
			if tt.wantErr != "" {
				if got.err == nil || got.err.Error() != tt.wantErr {
					t.Fatalf("CONNECT error = %v, want %q", got.err, tt.wantErr)
				}
				return
			}
			if got.err != nil {
				t.Fatal(got.err)
			}
			expectRead(t, got.conn, "tunnel greeting")
			f := await(t, a.request)
			if f.ServerConn != proxy || f.Live {
				t.Fatalf("CONNECT flow = %+v, want non-live flow on physical proxy", f)
			}
			if diff := gocmp.Diff(tt.head, f.Request.Authority); diff != "" {
				t.Fatalf("CONNECT authority (-want +got):\n%s", diff)
			}
		})
	}
}
