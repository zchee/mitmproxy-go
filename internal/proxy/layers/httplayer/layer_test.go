// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(layertest.Timeout):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("operation did not complete:\n%s", buf[:n])
		var zero T
		return zero
	}
}

// pipePool opens real loopback sockets and hands the origin side to the
// test, caching established connections by destination as the handler's
// pool reuses them.
type pipePool struct {
	t       *testing.T
	origins chan layer.Conn

	mu     sync.Mutex
	opens  int
	err    error
	cached map[string]pooled
}

type pooled struct {
	conn layer.Conn
	srv  *connection.Server
}

func newPipePool(t *testing.T) *pipePool {
	return &pipePool{t: t, origins: make(chan layer.Conn, 2), cached: make(map[string]pooled)}
}

func (p *pipePool) openCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.opens
}

func (p *pipePool) Open(ctx context.Context, srv *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	key := fmt.Sprintf("%v|%v", srv.Address, srv.TLS)
	p.mu.Lock()
	if entry, ok := p.cached[key]; ok && opts.Reuse {
		p.mu.Unlock()
		return entry.conn, entry.srv, nil
	}
	p.opens++
	err := p.err
	p.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	proxySide, originSide := layertest.Pipe(p.t)
	conn := proxySide
	if opts.Setup != nil {
		wrapped, err := opts.Setup(ctx, conn, srv)
		if err != nil {
			return nil, nil, err
		}
		conn = wrapped
	}
	p.mu.Lock()
	p.cached[key] = pooled{conn: conn, srv: srv}
	p.mu.Unlock()
	select {
	case p.origins <- originSide:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	return conn, srv, nil
}

func (p *pipePool) Upgrade(_ context.Context, srv *connection.Server, _ func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) (layer.Conn, *connection.Server, error) {
	return nil, srv, errors.New("pipePool: Upgrade is not used by these tests")
}

func (*pipePool) Lookup(*connection.Server) (layer.Conn, bool) { return nil, false }

// Retire drops the cached lease without closing either side of its real socket.
func (p *pipePool) Retire(srv *connection.Server) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, entry := range p.cached {
		if entry.srv == srv {
			delete(p.cached, key)
		}
	}
}

type layerSession struct {
	t        *testing.T
	m        *master.Master
	a        *streamAddon
	c        *layer.Context
	client   layer.Conn
	pool     *pipePool
	done     chan error
	finished chan struct{}
}

func newLayerSession(t *testing.T, a *streamAddon, specs ...string) *layerSession {
	t.Helper()
	m := master.New(master.Config{})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	if a == nil {
		a = &streamAddon{}
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Addons.Add(ctx, a)
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "eager",
		"Determine when server connections should be established. When set to lazy, mitmproxy "+
			"tries to defer establishing an upstream connection as long as possible. This makes it possible to "+
			"use server replay while being offline. When set to eager, mitmproxy can detect protocols with "+
			"server-side greetings, as well as accurately mirror TLS ALPN negotiation.",
		options.WithChoices("eager", "lazy")); err != nil {
		t.Fatal(err)
	}
	if err := m.Options.Add(t.Context(), "keep_host_header", options.TypeBool, false,
		"Reverse Proxy: Keep the original host header instead of rewriting it to the reverse proxy target."); err != nil {
		t.Fatal(err)
	}
	if err := m.Options.Add(t.Context(), "validate_inbound_headers", options.TypeBool, true,
		"Make sure that incoming HTTP requests and responses are not malformed. Disabling this "+
			"option makes mitmproxy vulnerable to HTTP smuggling attacks."); err != nil {
		t.Fatal(err)
	}
	if len(specs) != 0 {
		if err := m.Do(t.Context(), func(ctx context.Context) error {
			return m.Options.Set(ctx, specs...)
		}); err != nil {
			t.Fatal(err)
		}
	}
	clientSide, clientInput := layertest.Pipe(t)
	pool := newPipePool(t)
	return &layerSession{
		t: t, m: m, a: a, client: clientSide, pool: pool,
		c: &layer.Context{
			Data: &hookdata.Context{
				Client: connection.NewClient(connection.Address{}, connection.Address{}, 1),
				Server: connection.NewServer(nil), Options: m.Options,
			},
			Client: proxy.Record(clientInput), Record: proxy.Record,
			Hooks: &proxy.HookRunner{Manager: m.Addons}, Do: m.Do, Pool: pool,
		},
	}
}

func (s *layerSession) start(mode hookdata.HTTPMode) {
	s.t.Helper()
	l, err := layer.Build(s.t.Context(), s.c, hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: mode}})
	if err != nil {
		s.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(s.t.Context())
	s.done = make(chan error, 1)
	s.finished = make(chan struct{})
	s.t.Cleanup(func() {
		cancel()
		await(s.t, s.finished)
	})
	go func() {
		s.done <- l.Run(ctx, s.c)
		close(s.finished)
	}()
}

func write(t *testing.T, conn layer.Conn, data string) {
	t.Helper()
	if _, err := conn.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
}

func expectRead(t *testing.T, conn layer.Conn, expected string) {
	t.Helper()
	got := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read %q: %v", got, err)
	}
	if diff := gocmp.Diff(expected, string(got)); diff != "" {
		t.Fatal(diff)
	}
}

// readThrough reads until the data received so far ends in suffix.
func readThrough(t *testing.T, conn layer.Conn, suffix string) []byte {
	t.Helper()
	var data []byte
	buf := make([]byte, 4096)
	for !bytes.HasSuffix(data, []byte(suffix)) {
		n, err := conn.Read(buf)
		data = append(data, buf[:n]...)
		if err != nil {
			t.Fatalf("read %q waiting for %q: %v", data, suffix, err)
		}
	}
	return data
}

func TestLayerBuild(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mode      hookdata.HTTPMode
		proxyMode string
		reverse   bool
		wantErr   bool
	}{
		"success: regular":                {mode: hookdata.HTTPModeRegular},
		"success: transparent":            {mode: hookdata.HTTPModeTransparent},
		"success: upstream":               {mode: hookdata.HTTPModeUpstream},
		"success: reverse proxy detected": {mode: hookdata.HTTPModeTransparent, proxyMode: "reverse:https://example.com", reverse: true},
		"error: missing mode":             {wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newLayerSession(t, nil)
			if tt.proxyMode != "" {
				s.c.Data.Client.ProxyMode = tt.proxyMode
			}
			built, err := layer.Build(t.Context(), s.c, hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: tt.mode}})
			if tt.wantErr {
				if err == nil {
					t.Fatal("Build succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if built.Kind() != hookdata.LayerHTTP {
				t.Fatalf("Kind() = %v", built.Kind())
			}
			if got := built.(*httpLayer).route.reverse; got != tt.reverse {
				t.Fatalf("reverse = %v, want %v", got, tt.reverse)
			}
		})
	}
}

// Upstream test_simple and test_multiple_server_connections' reuse half: two
// keep-alive exchanges travel one lazily opened server connection, with the
// absolute-form target downgraded to origin form.
func TestLayerRegularExchanges(t *testing.T) {
	t.Parallel()
	a := &streamAddon{}
	s := newLayerSession(t, a, "connection_strategy=lazy")
	s.start(hookdata.HTTPModeRegular)

	write(t, s.client, "GET http://origin.test/one HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	origin := await(t, s.pool.origins)
	expectRead(t, origin, "GET /one HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	write(t, origin, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
	expectRead(t, s.client, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")

	write(t, s.client, "GET http://origin.test/two HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	expectRead(t, origin, "GET /two HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	write(t, origin, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
	expectRead(t, s.client, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")

	if err := s.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	if got := s.pool.openCount(); got != 1 {
		t.Fatalf("pool opened %d connections, want 1", got)
	}
	want := []string{
		"requestheaders", "request", "responseheaders", "response",
		"requestheaders", "request", "responseheaders", "response",
	}
	if diff := gocmp.Diff(want, s.a.calls); diff != "" {
		t.Fatal(diff)
	}
}

// Upstream test_response_until_eof: a handler-supplied response at
// requestheaders reaches the client without any server connection.
func TestLayerSyntheticResponse(t *testing.T) {
	t.Parallel()
	a := &streamAddon{}
	a.edit = func(name string, f *flow.HTTPFlow) {
		if name == "requestheaders" {
			response, err := httpmsg.MakeResponse(418, []byte("teapot"), nil)
			if err != nil {
				t.Error(err)
				return
			}
			f.Response = response
		}
	}
	s := newLayerSession(t, a, "connection_strategy=lazy")
	s.start(hookdata.HTTPModeRegular)

	write(t, s.client, "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	response := readThrough(t, s.client, "teapot")
	if !bytes.HasPrefix(response, []byte("HTTP/1.1 418 ")) {
		t.Fatalf("response = %q, want a 418 status line", response)
	}
	if err := s.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	if got := s.pool.openCount(); got != 0 {
		t.Fatalf("pool opened %d connections, want 0", got)
	}
	want := []string{"requestheaders", "request", "responseheaders", "response"}
	if diff := gocmp.Diff(want, s.a.calls); diff != "" {
		t.Fatal(diff)
	}
}

// Upstream test_disconnect_while_intercept's connect-failure half: a lazy
// acquisition that cannot reach the origin answers with upstream's 502 and
// fires the error hook.
func TestLayerLazyConnectFailure(t *testing.T) {
	t.Parallel()
	a := &streamAddon{}
	s := newLayerSession(t, a, "connection_strategy=lazy")
	s.pool.err = errors.New("dial refused")
	s.start(hookdata.HTTPModeRegular)

	write(t, s.client, "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	response, err := io.ReadAll(s.client)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(response, []byte("HTTP/1.1 502 ")) {
		t.Fatalf("response = %q, want a 502 status line", response)
	}
	if !strings.Contains(string(response), "dial refused") {
		t.Fatalf("response %q does not carry the connection error", response)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	want := []string{"requestheaders", "request", "error"}
	if diff := gocmp.Diff(want, s.a.calls); diff != "" {
		t.Fatal(diff)
	}
}

// tunnelChild stands in for the protocol layer a CONNECT hands over to.
type tunnelChild struct {
	received chan []byte
}

func (*tunnelChild) Kind() hookdata.LayerKind { return hookdata.LayerTCP }

func (l *tunnelChild) Run(_ context.Context, c *layer.Context) error {
	c.Client.StopRecording()
	early := make([]byte, len("early-bytes"))
	if _, err := io.ReadFull(c.Client, early); err != nil {
		return err
	}
	l.received <- slices.Clone(early)
	if _, err := c.Client.Write(early); err != nil {
		return err
	}
	if c.Server == nil {
		return errors.New("the eager CONNECT connection did not reach the child")
	}
	_, err := c.Server.Write([]byte("origin-ping"))
	return err
}

// Upstream test_http_proxy CONNECT half and test_connect_unauthorized's
// mirror: an eager CONNECT proves the destination, answers 200 without
// headers, and hands the tunnel bytes to the next layer.
func TestLayerConnectTunnel(t *testing.T) {
	t.Parallel()
	a := &streamAddon{}
	s := newLayerSession(t, a, "connection_strategy=eager")
	child := &tunnelChild{received: make(chan []byte, 1)}
	s.c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
		return child, nil
	}
	s.start(hookdata.HTTPModeRegular)

	write(t, s.client, "CONNECT origin.test:443 HTTP/1.1\r\n\r\n")
	write(t, s.client, "early-bytes")
	expectRead(t, s.client, "HTTP/1.1 200 Connection established\r\n\r\n")
	if diff := gocmp.Diff([]byte("early-bytes"), await(t, child.received)); diff != "" {
		t.Fatal(diff)
	}
	expectRead(t, s.client, "early-bytes")
	origin := await(t, s.pool.origins)
	expectRead(t, origin, "origin-ping")
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	if got := s.pool.openCount(); got != 1 {
		t.Fatalf("pool opened %d connections, want 1", got)
	}
	want := []string{"http_connect", "http_connected"}
	if diff := gocmp.Diff(want, s.a.calls); diff != "" {
		t.Fatal(diff)
	}
}

// Upstream test_transparent_sni-adjacent routing: in transparent mode the
// destination comes from the connection metadata and the request head is
// forwarded in origin form.
func TestLayerTransparentDestination(t *testing.T) {
	t.Parallel()
	a := &streamAddon{}
	s := newLayerSession(t, a, "connection_strategy=lazy")
	s.c.Data.Server = connection.NewServer(&connection.Address{Host: "origin.test", Port: 80})
	s.start(hookdata.HTTPModeTransparent)

	write(t, s.client, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	origin := await(t, s.pool.origins)
	expectRead(t, origin, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	write(t, origin, "HTTP/1.1 204 No Content\r\n\r\n")
	expectRead(t, s.client, "HTTP/1.1 204 No Content\r\n\r\n")

	if err := s.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	server := s.pool.cached[fmt.Sprintf("%v|%v", &connection.Address{Host: "origin.test", Port: 80}, false)]
	if server.srv == nil || server.srv.Address == nil || server.srv.Address.Host != "origin.test" {
		t.Fatalf("pool dialed %+v, want origin.test", server.srv)
	}
}
