// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

// TestReverseHTTPSHost extends test_modes.test_reverse_proxy to a TLS origin.
func TestReverseHTTPSHost(t *testing.T) {
	tests := map[string]struct {
		target   string
		keepHost bool
		wantHost string
	}{
		"success: default HTTPS port":    {target: "example.test:443", wantHost: "example.test"},
		"success: nondefault HTTPS port": {target: "example.test:8443", wantHost: "example.test:8443"},
		"success: preserve client host":  {target: "example.test:443", keepHost: true, wantHost: "client.test:8080"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			heads := make(chan string, 1)
			origin := proxytest.StartTLSOrigin(t, []string{"example.test"}, func(conn net.Conn) {
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					t.Error(err)
					return
				}
				_ = request.Body.Close()
				heads <- request.Method + " " + request.RequestURI + " " + request.Proto + "\r\nHost: " + request.Host + "\r\n"
				_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n")
			})
			p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin), proxytest.WithOptions(map[string]any{
				"mode": []string{"reverse:https://" + tt.target}, "keep_host_header": tt.keepHost,
			}))
			response, body := httpExchange(t, dial(t, p.Addr), "GET /hello HTTP/1.1\r\nHost: client.test:8080\r\n\r\n")
			if response.StatusCode != http.StatusNoContent || len(body) != 0 {
				t.Fatalf("reverse HTTPS response = %d %q", response.StatusCode, body)
			}
			if diff := gocmp.Diff("GET /hello HTTP/1.1\r\nHost: "+tt.wantHost+"\r\n", receive(t, heads)); diff != "" {
				t.Fatalf("origin request (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReverseEagerConnect(t *testing.T) {
	tests := map[string]struct{ secure bool }{
		"success: HTTP origin":  {},
		"success: HTTPS origin": {secure: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			accepted := make(chan struct{}, 1)
			handler := func(conn net.Conn) {
				accepted <- struct{}{}
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					t.Error(err)
					return
				}
				_ = request.Body.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n")
			}
			var origin *proxytest.Origin
			target := "http://example.test:80"
			if tt.secure {
				origin = proxytest.StartTLSOrigin(t, []string{"example.test"}, handler)
				target = "https://example.test:443"
			} else {
				origin = proxytest.StartOrigin(t, handler)
			}
			p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin), proxytest.WithOptions(map[string]any{
				"mode": []string{"reverse:" + target}, "connection_strategy": "eager",
			}))
			client := dial(t, p.Addr)
			// The origin accepts before this client sends even a request header.
			receive(t, accepted)
			response, _ := httpExchange(t, client, "GET / HTTP/1.1\r\nHost: client.test\r\n\r\n")
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("reverse response = %d", response.StatusCode)
			}
		})
	}
}
