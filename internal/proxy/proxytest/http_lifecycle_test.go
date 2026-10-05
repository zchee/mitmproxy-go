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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

// TestHTTPStartStop ports test_proxyserver.test_start_stop over regular and upstream proxies.
func TestHTTPStartStop(t *testing.T) {
	tests := map[string]struct{ upstream bool }{
		"success: regular":  {},
		"success: upstream": {upstream: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			heads := make(chan string, 2)
			origin := proxytest.StartOrigin(t, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				for {
					var head strings.Builder
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							return
						}
						head.WriteString(line)
						if line == "\r\n" {
							break
						}
					}
					heads <- head.String()
					if _, err := io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n"); err != nil {
						return
					}
				}
			})
			p := startHTTPMode(t, origin, tt.upstream)
			client := dial(t, p.Addr)
			response, _ := httpExchange(t, client, "GET http://example.test/hello HTTP/1.1\r\n\r\n")
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("response = %d", response.StatusCode)
			}
			if diff := gocmp.Diff("GET /hello HTTP/1.1\r\n\r\n", receive(t, heads)); diff != "" {
				t.Fatalf("origin request (-want +got):\n%s", diff)
			}
			if p.Server.ActiveConnections(t.Context()) != 1 || p.Server.String() != "Proxyserver(1 active conns)" {
				t.Fatalf("proxy state = %s", p.Server)
			}
			if err := p.Server.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				return p.Master.Options.Update(ctx, map[string]any{"server": false})
			}); err != nil {
				t.Fatal(err)
			}
			if err := p.Server.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			if addrs := p.Server.ListenAddrs(); len(addrs) != 0 {
				t.Fatalf("listeners still active after server=false: %v", addrs)
			}
			response, _ = httpExchange(t, client, "GET http://example.test/after-stop HTTP/1.1\r\n\r\n")
			if response.StatusCode != http.StatusNoContent {
				t.Fatal("stopping listeners interrupted the accepted HTTP connection")
			}
			if diff := gocmp.Diff("GET /after-stop HTTP/1.1\r\n\r\n", receive(t, heads)); diff != "" {
				t.Fatal(diff)
			}
			awaitHook(t, p, "response")
			if err := p.Master.Do(t.Context(), func(context.Context) error {
				for _, call := range p.Recorder.Calls() {
					if call.Hook == "response" {
						f := call.Arg.(*flow.HTTPFlow)
						if f.Response.StatusCode != http.StatusNoContent {
							t.Errorf("recorded response status = %d", f.Response.StatusCode)
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCONNECTInjection ports test_proxyserver.test_inject with real sockets.
func TestCONNECTInjection(t *testing.T) {
	tests := map[string]struct{ upstream bool }{
		"success: regular":  {},
		"success: upstream": {upstream: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin := proxytest.StartOrigin(t, func(conn net.Conn) {
				buf := make([]byte, 1)
				for {
					if _, err := io.ReadFull(conn, buf); err != nil {
						return
					}
					if _, err := io.WriteString(conn, strings.ToUpper(string(buf))); err != nil {
						return
					}
				}
			})
			flows := &captureTCPFlow{flows: make(chan *flow.TCPFlow, 1)}
			p := startHTTPMode(t, origin, tt.upstream, proxytest.WithAddons(flows))
			client := dial(t, p.Addr)
			connectTunnel(t, client, "example.test:443")
			if _, err := io.WriteString(client, "a"); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1)
			if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "A" {
				t.Fatalf("tunnel response = %q, %v", buf, err)
			}
			f := receive(t, flows.flows)
			injections := map[string]struct {
				toClient bool
				message  string
				want     string
			}{
				"to origin": {message: "b", want: "B"},
				"to client": {toClient: true, message: "c", want: "c"},
			}
			for _, injection := range injections {
				if _, err := p.Master.Call(t.Context(), "inject.tcp", f, injection.toClient, []byte(injection.message)); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(client, buf); err != nil || string(buf) != injection.want {
					t.Fatalf("injected response = %q, %v; want %q", buf, err, injection.want)
				}
			}
		})
	}
}

type captureTCPFlow struct{ flows chan *flow.TCPFlow }

func (a *captureTCPFlow) TCPStart(_ context.Context, f *flow.TCPFlow) error {
	a.flows <- f
	return nil
}

func startHTTPMode(t *testing.T, origin *proxytest.Origin, upstream bool, opts ...proxytest.Option) *proxytest.Proxy {
	t.Helper()
	if upstream {
		parent := proxytest.Start(t, proxytest.WithOrigin("example.test", origin))
		opts = append(opts, proxytest.WithOptions(map[string]any{"mode": []string{"upstream:http://" + parent.Addr}}))
	} else {
		opts = append(opts, proxytest.WithOrigin("example.test", origin))
	}
	return proxytest.Start(t, opts...)
}

type holdHTTPFlows struct {
	flows   chan *flow.HTTPFlow
	entered chan struct{}
	release chan struct{}
}

func (a *holdHTTPFlows) Request(ctx context.Context, f *flow.HTTPFlow) error {
	switch f.Request.Path {
	case "/intercepted":
		f.Intercept()
		a.flows <- f
	case "/held":
		close(a.entered)
		select {
		case <-a.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestWatchdogHTTPHookAndInterceptionIsolation(t *testing.T) {
	origin := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	hooks := &holdHTTPFlows{flows: make(chan *flow.HTTPFlow, 1), entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(hooks.release) })
	p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin), proxytest.WithAddons(hooks), proxytest.WithOptions(map[string]any{"tcp_timeout": 1}))
	t.Cleanup(release)
	idle := dial(t, p.Addr)
	// The silent HTTP client must finish its connection hook before another
	// request holds dispatch and leaves this client's watchdog suspended.
	awaitHook(t, p, "client_connected")
	intercepted := dial(t, p.Addr)
	if _, err := io.WriteString(intercepted, "GET http://example.test/intercepted HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	f := receive(t, hooks.flows)
	held := dial(t, p.Addr)
	if _, err := io.WriteString(held, "GET http://example.test/held HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	receive(t, hooks.entered)
	// A lower bound demonstrates that both hook execution and interception
	// remain exempt from the one-second inactivity timeout.
	time.Sleep(4 * time.Second)
	if _, err := idle.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle connection read = %v, want watchdog closure", err)
	}
	release()
	for conn, want := range map[net.Conn]string{held: "/held", intercepted: "/intercepted"} {
		if conn == intercepted {
			if err := p.Master.Do(t.Context(), func(context.Context) error { f.Resume(); return nil }); err != nil {
				t.Fatal(err)
			}
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("protected connection expired: %v", err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff(want, string(body)); diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestHTTPSelfConnectErrorResponse(t *testing.T) {
	p := proxytest.Start(t)
	response, body := httpExchange(t, dial(t, p.Addr), "GET http://"+p.Addr+"/ HTTP/1.1\r\nHost: "+p.Addr+"\r\n\r\n")
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "Request destination unknown. Unable to figure out where this request should be forwarded to.") {
		t.Fatalf("self-connect response = %d %q", response.StatusCode, body)
	}
	for _, hook := range p.Recorder.Hooks() {
		if hook == "server_connected" {
			t.Fatal("self-connect reached the proxy listener")
		}
	}
}
