// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
)

func TestLayerUpstreamRedirectMatrix(t *testing.T) {
	tests := map[string]struct{ destination, proxy bool }{
		"success: reuse":              {},
		"success: change destination": {destination: true},
		"success: change proxy":       {proxy: true},
	}
	protocols := map[string]struct{ tunnel bool }{"HTTP": {}, "CONNECT": {tunnel: true}}
	hosts := map[string]struct{ wire, logical string }{
		"ASCII": {"example.com", "example.com"},
		"IDNA":  {"xn--bcher-kva.test", "bücher.test"},
	}
	for name, route := range tests {
		for protocol, transport := range protocols {
			for hostName, host := range hosts {
				t.Run(name+"/"+protocol+"/"+hostName, func(t *testing.T) {
					var servers []*connection.Server
					a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
						if name == "request" && f.Request.Path == "/two" {
							if route.destination {
								f.Request.SetHost(f.Request.Host + ".test")
								f.Request.SetHostHeader(host.wire)
							}
							if route.proxy {
								f.ServerConn.Via = &connection.ServerSpec{Scheme: "http", Address: connection.Address{Host: "other-proxy", Port: 1234}}
							}
						}
						if name == "response" {
							servers = append(servers, f.ServerConn.Clone())
						}
					}}
					pool, peers, observer := newUpstreamPoolSession(t)
					s := newLayerSession(t, a, "connection_strategy=lazy")
					s.c.Pool = pool.base
					s.c.Data.Client.ProxyMode = "upstream:http://proxy:8080"
					s.c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
						return &httpLayer{route: routeConfig{mode: modeTransparent}}, nil
					}
					s.start(hookdata.HTTPModeUpstream)
					if transport.tunnel {
						write(t, s.client, "CONNECT "+host.wire+":443 HTTP/1.1\r\nHost: "+host.wire+":443\r\n\r\n")
						expectRead(t, s.client, "HTTP/1.1 200 Connection established\r\n\r\n")
					}
					var origin layer.Conn
					for i, path := range []string{"/", "/two"} {
						target := "http://" + host.wire + path
						if transport.tunnel {
							target = path
						}
						write(t, s.client, "GET "+target+" HTTP/1.1\r\nHost: "+host.wire+"\r\n\r\n")
						destination := host.wire
						if i == 1 && route.destination {
							destination += ".test"
						}
						if i == 0 || route.destination || route.proxy {
							origin = await(t, peers)
							if transport.tunnel {
								expectRead(t, origin, "CONNECT "+destination+":443 HTTP/1.1\r\nHost: "+destination+":443\r\n\r\n")
								write(t, origin, "HTTP/1.1 200 Connection established\r\n\r\n")
							}
						}
						forward := "http://" + destination + path
						if transport.tunnel {
							forward = path
						}
						expectRead(t, origin, "GET "+forward+" HTTP/1.1\r\nHost: "+host.wire+"\r\n\r\n")
						write(t, origin, "HTTP/1.1 418 OK\r\nContent-Length: 0\r\n\r\n")
						expectRead(t, s.client, "HTTP/1.1 418 OK\r\nContent-Length: 0\r\n\r\n")
					}
					hooks := []string{"requestheaders", "request", "responseheaders", "response", "requestheaders", "request", "responseheaders", "response"}
					if transport.tunnel {
						hooks = append([]string{"http_connect", "http_connected"}, hooks...)
					}
					finishLayerSession(t, s, hooks)
					wantOpens := 1
					if route.destination || route.proxy {
						wantOpens++
					}
					if len(observer.connected) != wantOpens || len(servers) != 2 {
						t.Fatalf("opens=%d servers=%d, want %d and 2", len(observer.connected), len(servers), wantOpens)
					}
					if (servers[0].ID == servers[1].ID) != (wantOpens == 1) {
						t.Fatalf("logical connection reuse = %s -> %s", servers[0].ID, servers[1].ID)
					}
					wantHost := host.logical
					if route.destination {
						wantHost += ".test"
					}
					if servers[1].Address.Host != wantHost {
						t.Fatalf("logical host = %q, want %q", servers[1].Address.Host, wantHost)
					}
					wantProxy := connection.Address{Host: "proxy", Port: 8080}
					if route.proxy {
						wantProxy = connection.Address{Host: "other-proxy", Port: 1234}
					}
					if diff := gocmp.Diff(wantProxy, servers[1].Via.Address); diff != "" {
						t.Fatalf("proxy (-want +got):\n%s", diff)
					}
				})
			}
		}
	}
}

func TestLayerConnectTCPMatrix(t *testing.T) {
	tests := map[string]struct{ mode hookdata.HTTPMode }{
		"regular":  {hookdata.HTTPModeRegular},
		"upstream": {hookdata.HTTPModeUpstream},
	}
	closers := map[string]struct{ client bool }{"client first": {true}, "server first": {false}}
	for modeName, mode := range tests {
		for closeName, closer := range closers {
			t.Run("success: "+modeName+"/"+closeName, func(t *testing.T) {
				pool, peers, _ := newUpstreamPoolSession(t)
				s := newLayerSession(t, nil, "connection_strategy=lazy")
				s.c.Pool = pool.base
				if mode.mode == hookdata.HTTPModeUpstream {
					s.c.Data.Client.ProxyMode = "upstream:http://proxy:8080"
				}
				s.c.NextLayer = func(ctx context.Context, c *layer.Context) (layer.Layer, error) {
					return layer.Build(ctx, c, hookdata.LayerStack{{Kind: hookdata.LayerTCP}})
				}
				observer := &upgradeObserver{started: make(chan *flow.TCPFlow, 1)}
				if err := s.m.Addons.Add(t.Context(), observer); err != nil {
					t.Fatal(err)
				}
				inject := make(chan layer.Injected, 1)
				s.c.Inject = inject
				s.start(mode.mode)
				write(t, s.client, "CONNECT example:443 HTTP/1.1\r\nHost: example:443\r\n\r\n")
				expectRead(t, s.client, "HTTP/1.1 200 Connection established\r\n\r\n")
				write(t, s.client, "this is not http")
				origin := await(t, peers)
				if mode.mode == hookdata.HTTPModeUpstream {
					expectRead(t, origin, "CONNECT example:443 HTTP/1.1\r\nHost: example:443\r\n\r\n")
					write(t, origin, "HTTP/1.1 200 Connection established\r\n\r\n")
				}
				expectRead(t, origin, "this is not http")
				write(t, origin, "true that")
				expectRead(t, s.client, "true that")
				f := await(t, observer.started)
				const injected = "fake news from your friendly man-in-the-middle"
				inject <- layer.Injected{Flow: f, Message: tcp.NewMessage(false, []byte(injected))}
				expectRead(t, s.client, injected)
				first, second := origin, s.client
				if closer.client {
					first, second = second, first
				}
				if err := first.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if data, err := io.ReadAll(second); err != nil || len(data) != 0 {
					t.Fatalf("first close = (%q, %v)", data, err)
				}
				if err := second.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if data, err := io.ReadAll(first); err != nil || len(data) != 0 {
					t.Fatalf("second close = (%q, %v)", data, err)
				}
				if err := await(t, s.done); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff([]string{"tcp_start", "tcp_end"}, observer.lifecycle); diff != "" {
					t.Fatal(diff)
				}
				if diff := gocmp.Diff(map[bool]string{true: "this is not http", false: "true that" + injected}, observer.content); diff != "" {
					t.Fatal(diff)
				}
			})
		}
	}
}

func TestLayerOriginalServerDisconnects(t *testing.T) {
	pool, peers, observer := newUpstreamPoolSession(t)
	s := newLayerSession(t, nil)
	s.c.Pool = pool.base
	server := connection.NewServer(&connection.Address{Host: "example.com", Port: 80})
	conn, actual, err := pool.base.Open(t.Context(), server, layer.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	origin := await(t, peers)
	connected := await(t, observer.connected)
	s.c.Data.Server = actual
	s.c.Server = s.c.Record(conn)
	s.start(hookdata.HTTPModeTransparent)
	if err := origin.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if data, err := io.ReadAll(origin); err != nil || len(data) != 0 {
		t.Fatalf("idle origin retirement = (%q, %v)", data, err)
	}
	closed := await(t, observer.disconnected)
	if closed.ID != connected.ID || closed.State != connection.Closed {
		t.Fatalf("retirement = %+v, want closed %s", closed, connected.ID)
	}
	finishLayerSession(t, s, nil)
}
