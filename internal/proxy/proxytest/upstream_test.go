// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/upstreamauth"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestUpstreamProxyWire(t *testing.T) {
	tests := map[string]struct {
		connect bool
		refuse  bool
	}{
		"success: absolute HTTP target and authentication": {},
		"success: CONNECT authentication and tunnel":       {connect: true},
		"error: CONNECT authentication refused":            {connect: true, refuse: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			heads := make(chan string, 1)
			parent := proxytest.StartOrigin(t, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				var head strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						t.Error(err)
						return
					}
					head.WriteString(line)
					if line == "\r\n" {
						break
					}
				}
				heads <- head.String()
				switch {
				case tt.refuse:
					_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
				case tt.connect:
					if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
						return
					}
					_, _ = io.Copy(conn, reader)
				default:
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nparent")
				}
			})
			p := proxytest.Start(t, proxytest.WithOrigin("parent.test", parent), proxytest.WithOptions(map[string]any{
				"mode": []string{"upstream:http://parent.test:8080"},
			}))
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				if err := p.Master.Addons.Add(ctx, upstreamauth.New(p.Master.Options)); err != nil {
					return err
				}
				return p.Master.Options.Update(ctx, map[string]any{"upstream_auth": new("test:test")})
			}); err != nil {
				t.Fatal(err)
			}
			client := dial(t, p.Addr)
			wantHead := "GET http://example.test/hello?x=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"
			switch {
			case tt.refuse:
				// Upstream 3368a0a: http/__init__.py:802-845 acknowledges CONNECT;
				// tunnel.py:129-140 defers the parent dial until the child requests it.
				// _upstream_proxy.py:105-112 returns the refusal diagnostic;
				// tunnel.py:166-168 closes the parent and :100-109 replies with it.
				// http/__init__.py:757-767 and :723-755 send the tunneled HTTP error;
				// _events.py:111-117 maps it to 502; _http1.py:269-277 and :483-496
				// send the HTML body from _base.py:43-61 and close the client.
				connectTunnel(t, client, "example.test:443")
				response, body := httpExchange(t, client, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
				const diagnostic = "Upstream proxy parent.test:8080 refused HTTP CONNECT request: 407 Proxy Authentication Required"
				const wantBody = "<html>\n<head>\n    <title>502 Bad Gateway</title>\n</head>\n<body>\n    <h1>502 Bad Gateway</h1>\n    <p>" + diagnostic + "</p>\n</body>\n</html>"
				if response.Status != "502 Bad Gateway" || response.Header.Get("Content-Type") != "text/html" || !response.Close {
					t.Fatalf("refused CONNECT response = %s, headers %v, close %v; want 502 HTML with connection close", response.Status, response.Header, response.Close)
				}
				if diff := gocmp.Diff(wantBody, string(body)); diff != "" {
					t.Fatalf("refused CONNECT body (-want +got):\n%s", diff)
				}
				if n, err := client.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("client after refusal = %d bytes, %v; want EOF", n, err)
				}
			case tt.connect:
				connectTunnel(t, client, "example.test:443")
				exchange(t, client, "tunnel bytes cross the parent")
			default:
				response, body := httpExchange(t, client, "GET http://example.test/hello?x=1 HTTP/1.1\r\nHost: example.test\r\n\r\n")
				if response.StatusCode != http.StatusOK || string(body) != "parent" {
					t.Fatalf("parent response = %d %q", response.StatusCode, body)
				}
			}
			if tt.connect {
				wantHead = "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"
				awaitHook(t, p, "http_connect_upstream")
				if err := p.Master.Do(t.Context(), func(context.Context) error {
					var calls int
					for _, call := range p.Recorder.Calls() {
						if call.Hook == "http_connect_upstream" {
							calls++
							f := call.Arg.(*flow.HTTPFlow)
							if f.Request.Authority != "example.test:443" {
								t.Errorf("upstream hook authority = %q", f.Request.Authority)
							}
						}
					}
					if calls != 1 {
						t.Errorf("http_connect_upstream calls = %d, want 1", calls)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			if diff := gocmp.Diff(wantHead, receive(t, heads)); diff != "" {
				t.Fatalf("parent wire request (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUpstreamModeSwitchKeepsAcceptedHTTP(t *testing.T) {
	original := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "original upstream")
	}))
	replacement := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "replacement reverse")
	}))
	p := startHTTPMode(t, original, true)
	client := dial(t, p.Addr)
	request := "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"
	response, body := httpExchange(t, client, request)
	if response.StatusCode != http.StatusOK || string(body) != "original upstream" {
		t.Fatalf("initial upstream response = %d %q", response.StatusCode, body)
	}
	if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
		return p.Master.Options.Update(ctx, map[string]any{"mode": []string{"reverse:http://" + replacement.Addr}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.Server.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	addrs := p.Server.ListenAddrs()
	if len(addrs) != 1 {
		t.Fatalf("replacement listeners = %v, want one", addrs)
	}
	response, body = httpExchange(t, dial(t, addrs[0].String()), "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	if response.StatusCode != http.StatusOK || string(body) != "replacement reverse" {
		t.Fatalf("replacement listener response = %d %q", response.StatusCode, body)
	}
	response, body = httpExchange(t, client, request)
	if response.StatusCode != http.StatusOK || string(body) != "original upstream" {
		t.Fatalf("accepted upstream connection after mode change = %d %q", response.StatusCode, body)
	}
}
