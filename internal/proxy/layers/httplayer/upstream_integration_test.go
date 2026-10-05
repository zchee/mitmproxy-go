// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/upstreamauth"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func expectRead(t *testing.T, reader io.Reader, want string) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read %q: %v", got, err)
	}
	if diff := gocmp.Diff(want, string(got)); diff != "" {
		t.Fatalf("wire bytes (-want +got):\n%s", diff)
	}
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(layertest.Timeout):
		t.Fatal("upstream observation did not complete")
		var zero T
		return zero
	}
}

func TestLayerUpstreamTunnel(t *testing.T) {
	tests := map[string]struct {
		proxyTLS  bool
		originTLS bool
	}{
		"success: plaintext tunnel":                   {},
		"success: TLS proxy with plaintext tunnel":    {proxyTLS: true},
		"success: TLS origin through plaintext proxy": {originTLS: true},
		"success: nested TLS through HTTPS proxy":     {proxyTLS: true, originTLS: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			originRequests := make(chan *http.Request, 1)
			serveOrigin := func(conn net.Conn) {
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					t.Errorf("origin request: %v", err)
					return
				}
				originRequests <- request
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}
			var origin *proxytest.Origin
			if tt.originTLS {
				origin = proxytest.StartTLSOrigin(t, []string{"origin.test"}, serveOrigin)
			} else {
				origin = proxytest.StartOrigin(t, serveOrigin)
			}
			connects := make(chan *http.Request, 1)
			proxySNI := make(chan string, 1)
			serveProxy := func(conn net.Conn) {
				br := bufio.NewReader(conn)
				request, err := http.ReadRequest(br)
				if err != nil {
					t.Errorf("upstream CONNECT: %v", err)
					return
				}
				select {
				case connects <- request:
				default:
					t.Error("unexpected second upstream CONNECT for one origin exchange")
					return
				}
				if tlsConn, ok := conn.(*tls.Conn); ok {
					proxySNI <- tlsConn.ConnectionState().ServerName
				}
				target, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", origin.Addr)
				if err != nil {
					t.Errorf("upstream origin dial: %v", err)
					return
				}
				defer func() { _ = target.Close() }()
				if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					t.Errorf("upstream CONNECT response: %v", err)
					return
				}
				uploaded := make(chan struct{})
				go func() {
					_, _ = io.Copy(target, br)
					_ = target.(*net.TCPConn).CloseWrite()
					close(uploaded)
				}()
				_, _ = io.Copy(conn, target)
				_ = conn.Close()
				_ = target.Close()
				<-uploaded
			}
			var upstream *proxytest.Origin
			scheme := "http"
			if tt.proxyTLS {
				scheme = "https"
				upstream = proxytest.StartTLSOrigin(t, []string{"proxy.test"}, serveProxy)
			} else {
				upstream = proxytest.StartOrigin(t, serveProxy)
			}
			p := proxytest.Start(t, proxytest.WithOrigin("proxy.test", upstream), proxytest.WithOrigin("origin.test", origin),
				proxytest.WithOptions(map[string]any{"mode": []string{"upstream:" + scheme + "://proxy.test:3128"}}))
			if err := p.Master.Addons.Add(t.Context(), upstreamauth.New(p.Master.Options)); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				return p.Master.Options.Update(ctx, map[string]any{"upstream_auth": new("test:password")})
			}); err != nil {
				t.Fatal(err)
			}
			client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", p.Addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(layertest.Timeout)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(client, "CONNECT origin.test:443 HTTP/1.1\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			expectRead(t, client, "HTTP/1.1 200 Connection established\r\n\r\n")
			if tt.originTLS {
				secure := tls.Client(client, &tls.Config{RootCAs: p.CAPool, ServerName: "origin.test", NextProtos: []string{"http/1.1"}})
				if err := secure.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				client = secure
			}
			if _, err := io.WriteString(client, "GET /tunnel HTTP/1.1\r\nHost: origin.test\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			expectRead(t, client, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			connect := await(t, connects)
			if connect.Method != "CONNECT" || connect.RequestURI != "origin.test:443" {
				t.Fatalf("upstream request = %s %s, want CONNECT origin.test:443", connect.Method, connect.RequestURI)
			}
			if got := connect.Header.Get("Proxy-Authorization"); got != "Basic dGVzdDpwYXNzd29yZA==" {
				t.Fatalf("upstream CONNECT auth = %q", got)
			}
			request := await(t, originRequests)
			if request.RequestURI != "/tunnel" {
				t.Fatalf("origin URI = %q, want origin form", request.RequestURI)
			}
			if tt.proxyTLS {
				if got := await(t, proxySNI); got != "proxy.test" {
					t.Fatalf("proxy SNI = %q, want proxy.test", got)
				}
			}
		})
	}
}

func TestLayerUpstreamHTTP(t *testing.T) {
	tests := map[string]struct {
		tls  bool
		auth bool
	}{
		"success: plaintext proxy":     {},
		"success: TLS proxy":           {tls: true},
		"success: authenticated proxy": {auth: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			type observation struct {
				head string
				sni  string
				err  error
			}
			observed := make(chan observation, 2)
			serve := func(conn net.Conn) {
				br := bufio.NewReader(conn)
				for range 2 {
					var head strings.Builder
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							observed <- observation{err: err}
							return
						}
						head.WriteString(line)
						if line == "\r\n" {
							break
						}
					}
					got := observation{head: head.String()}
					if tlsConn, ok := conn.(*tls.Conn); ok {
						got.sni = tlsConn.ConnectionState().ServerName
					}
					_, got.err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
					observed <- got
				}
			}
			var upstream *proxytest.Origin
			scheme := "http"
			if tt.tls {
				scheme = "https"
				upstream = proxytest.StartTLSOrigin(t, []string{"proxy.test"}, serve)
			} else {
				upstream = proxytest.StartOrigin(t, serve)
			}
			p := proxytest.Start(t,
				proxytest.WithOrigin("proxy.test", upstream),
				proxytest.WithOptions(map[string]any{"mode": []string{"upstream:" + scheme + "://proxy.test:3128"}}),
			)
			if tt.auth {
				if err := p.Master.Addons.Add(t.Context(), upstreamauth.New(p.Master.Options)); err != nil {
					t.Fatal(err)
				}
				if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
					return p.Master.Options.Update(ctx, map[string]any{"upstream_auth": new("test:password")})
				}); err != nil {
					t.Fatal(err)
				}
			}
			client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", p.Addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(layertest.Timeout)); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/first", "/second"} {
				head := "GET http://origin.test" + path + " HTTP/1.1\r\nHost: origin.test\r\n"
				if _, err := io.WriteString(client, head+"\r\n"); err != nil {
					t.Fatal(err)
				}
				expectRead(t, client.(*net.TCPConn), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				got := await(t, observed)
				if got.err != nil {
					t.Fatal(got.err)
				}
				if tt.auth {
					head += "Proxy-Authorization: Basic dGVzdDpwYXNzd29yZA==\r\n"
				}
				if diff := gocmp.Diff(head+"\r\n", got.head); diff != "" {
					t.Fatalf("upstream request (-want +got):\n%s", diff)
				}
				if tt.tls && got.sni != "proxy.test" {
					t.Fatalf("upstream TLS SNI = %q, want proxy.test", got.sni)
				}
			}
		})
	}
}
