// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

type redirectAddon struct {
	targets []string
	next    int
	servers chan *connection.Server
}

func (a *redirectAddon) Request(_ context.Context, f *flow.HTTPFlow) error {
	err := f.Request.SetURL(a.targets[a.next])
	a.next++
	return err
}

func (a *redirectAddon) Response(_ context.Context, f *flow.HTTPFlow) error {
	a.servers <- f.ServerConn.Clone()
	return nil
}

func dialHTTPPeer(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(layertest.Timeout)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func sendHTTPBytes(t *testing.T, conn net.Conn, data string) {
	t.Helper()
	if _, err := io.WriteString(conn, data); err != nil {
		t.Fatal(err)
	}
}

func TestLayerRedirect(t *testing.T) {
	tests := map[string]struct {
		strategy  string
		tunnel    bool
		originTLS bool
	}{
		"success: eager plain to plain":  {strategy: "eager"},
		"success: eager plain to TLS":    {strategy: "eager", originTLS: true},
		"success: eager tunnel to plain": {strategy: "eager", tunnel: true},
		"success: eager tunnel to TLS":   {strategy: "eager", tunnel: true, originTLS: true},
		"success: lazy plain to plain":   {strategy: "lazy"},
		"success: lazy plain to TLS":     {strategy: "lazy", originTLS: true},
		"success: lazy tunnel to plain":  {strategy: "lazy", tunnel: true},
		"success: lazy tunnel to TLS":    {strategy: "lazy", tunnel: true, originTLS: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			requests := make(chan *http.Request, 1)
			serve := func(conn net.Conn) {
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					t.Errorf("redirected request: %v", err)
					return
				}
				requests <- request
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}
			var origin *proxytest.Origin
			scheme, port := "http", 80
			if tt.originTLS {
				origin = proxytest.StartTLSOrigin(t, []string{"redirected.test"}, serve)
				scheme, port = "https", 443
			} else {
				origin = proxytest.StartOrigin(t, serve)
			}
			original := proxytest.StartEchoOrigin(t)
			addon := &redirectAddon{targets: []string{scheme + "://redirected.test/"}, servers: make(chan *connection.Server, 1)}
			p := proxytest.Start(t, proxytest.WithOrigin("original.test", original), proxytest.WithOrigin("redirected.test", origin), proxytest.WithAddons(addon), proxytest.WithOptions(map[string]any{"connection_strategy": tt.strategy}))
			client := dialHTTPPeer(t, p.Addr)
			target := "http://original.test/"
			if tt.tunnel {
				sendHTTPBytes(t, client, "CONNECT original.test:80 HTTP/1.1\r\nHost: original.test:80\r\n\r\n")
				expectRead(t, client, "HTTP/1.1 200 Connection established\r\n\r\n")
				target = "/"
			}
			sendHTTPBytes(t, client, "GET "+target+" HTTP/1.1\r\nHost: original.test\r\n\r\n")
			expectRead(t, client, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			request := await(t, requests)
			if request.RequestURI != "/" || request.Host != "redirected.test" {
				t.Fatalf("redirected request = %s, Host %q", request.RequestURI, request.Host)
			}
			server := await(t, addon.servers)
			if diff := gocmp.Diff(connection.Address{Host: "redirected.test", Port: port}, *server.Address); diff != "" {
				t.Fatalf("redirect destination (-want +got):\n%s", diff)
			}
			if server.TLS != tt.originTLS {
				t.Fatalf("origin TLS = %v, want %v", server.TLS, tt.originTLS)
			}
		})
	}
}

func TestLayerMultipleRewrittenDestinations(t *testing.T) {
	first := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Host) }))
	second := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Host) }))
	addon := &redirectAddon{targets: []string{"http://first.test/", "http://second.test/"}, servers: make(chan *connection.Server, 2)}
	p := proxytest.Start(t, proxytest.WithOrigin("first.test", first), proxytest.WithOrigin("second.test", second), proxytest.WithAddons(addon))
	client := dialHTTPPeer(t, p.Addr)
	reader := bufio.NewReader(client)
	var previousID string
	for _, host := range []string{"first.test", "second.test"} {
		sendHTTPBytes(t, client, "GET http://original.test/ HTTP/1.1\r\nHost: original.test\r\n\r\n")
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff(host, string(body)); diff != "" {
			t.Fatalf("rewritten host (-want +got):\n%s", diff)
		}
		server := await(t, addon.servers)
		if server.Address.Host != host || server.ID == previousID {
			t.Fatalf("connection = %+v, prior ID %s", server, previousID)
		}
		previousID = server.ID
	}
}

type interceptHTTPAddon struct {
	connect      bool
	held         chan *flow.HTTPFlow
	connected    chan *connection.Server
	disconnected chan *connection.Server
	clientClosed chan struct{}
}

func (a *interceptHTTPAddon) Request(_ context.Context, f *flow.HTTPFlow) error {
	if !a.connect {
		f.Intercept()
		a.held <- f
	}
	return nil
}

func (a *interceptHTTPAddon) HTTPConnect(_ context.Context, f *flow.HTTPFlow) error {
	if a.connect {
		f.Intercept()
		a.held <- f
	}
	return nil
}

func (a *interceptHTTPAddon) ServerConnected(_ context.Context, data *hookdata.ServerConnection) error {
	a.connected <- data.Server.Clone()
	return nil
}

func (a *interceptHTTPAddon) ServerDisconnected(_ context.Context, data *hookdata.ServerConnection) error {
	if a.disconnected != nil {
		a.disconnected <- data.Server.Clone()
	}
	return nil
}

func (a *interceptHTTPAddon) ClientDisconnected(_ context.Context, _ *connection.Client) error {
	close(a.clientClosed)
	return nil
}

func TestLayerDisconnectWhileIntercepted(t *testing.T) {
	var accepts atomic.Int32
	closeOrigin := make(chan struct{})
	originClosed := make(chan struct{})
	origin := proxytest.StartOrigin(t, func(conn net.Conn) {
		if accepts.Add(1) == 1 {
			<-closeOrigin
			_ = conn.Close()
			close(originClosed)
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			t.Errorf("reopened origin request: %v", err)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	closeFirst := sync.OnceFunc(func() { close(closeOrigin) })
	t.Cleanup(closeFirst)
	addon := &interceptHTTPAddon{held: make(chan *flow.HTTPFlow, 1), connected: make(chan *connection.Server, 2), disconnected: make(chan *connection.Server, 2), clientClosed: make(chan struct{})}
	p := proxytest.Start(t, proxytest.WithOrigin("origin.test", origin), proxytest.WithAddons(addon), proxytest.WithOptions(map[string]any{"connection_strategy": "eager"}))
	client := dialHTTPPeer(t, p.Addr)
	sendHTTPBytes(t, client, "CONNECT origin.test:80 HTTP/1.1\r\n\r\n")
	expectRead(t, client, "HTTP/1.1 200 Connection established\r\n\r\n")
	first := await(t, addon.connected)
	sendHTTPBytes(t, client, "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	f := await(t, addon.held)
	closeFirst()
	await(t, originClosed)
	if retired := await(t, addon.disconnected); retired.ID != first.ID {
		t.Fatalf("retired origin = %s, want %s", retired.ID, first.ID)
	}
	if err := p.Master.Do(t.Context(), func(context.Context) error { f.Resume(); return nil }); err != nil {
		t.Fatal(err)
	}
	expectRead(t, client, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	second := await(t, addon.connected)
	if first.ID == second.ID {
		t.Fatal("closed origin connection was reused")
	}
	if err := p.Master.Do(t.Context(), func(context.Context) error {
		if f.ServerConn.ID != second.ID || f.Live {
			t.Errorf("completed flow server=%s live=%v, want %s and not live", f.ServerConn.ID, f.Live, second.ID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLayerCloseDuringConnectHook(t *testing.T) {
	origin := proxytest.StartEchoOrigin(t)
	addon := &interceptHTTPAddon{connect: true, held: make(chan *flow.HTTPFlow, 1), connected: make(chan *connection.Server, 1), clientClosed: make(chan struct{})}
	p := proxytest.Start(t, proxytest.WithOrigin("origin.test", origin), proxytest.WithAddons(addon), proxytest.WithOptions(map[string]any{"connection_strategy": "eager"}))
	client := dialHTTPPeer(t, p.Addr)
	sendHTTPBytes(t, client, "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n")
	f := await(t, addon.held)
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// Wait for the proxy to observe the FIN while the hook is still paused.
	if data, err := io.ReadAll(client); err != nil || len(data) != 0 {
		t.Fatalf("paused CONNECT closure = (%q, %v), want EOF without a response", data, err)
	}
	if err := p.Master.Do(t.Context(), func(context.Context) error { f.Resume(); return nil }); err != nil {
		t.Fatal(err)
	}
	await(t, addon.clientClosed)
	select {
	case server := <-addon.connected:
		t.Fatalf("origin opened after client closed during CONNECT hook: %s", server.ID)
	default:
	}
}
