// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes_test

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/options"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/modes"
)

// Upstream test/mitmproxy/proxy/layers/test_modes.py coverage:
// test_upstream_https: TestExplicitProxyHandoff covers mode delegation; TLS,
//     absolute-form HTTP, CONNECT, and proxy authentication belong to HTTP/TLS tests.
// test_reverse_proxy: TestReverseDestination covers destination and SNI for both
//     keep_host_header values; HTTP Host rewriting belongs to the HTTP layer.
// test_reverse_proxy_tcp_over_tls: TestReverseConnectOrdering and TestConformance
//     cover eager/lazy handoff and replay; actual TLS wrapping belongs to TLS tests.
// test_reverse_eager_connect_failure: TestReverseConnectFailure.
// test_reverse_dns: deferred until DNS and datagram layers are available.
// test_quic: deferred until QUIC and HTTP/3 layers are available.
// test_udp: deferred until datagram transport is available.
// test_transparent_tcp, test_transparent_eager_connect_failure: deferred until
//     transparent proxy mode and original-destination lookup are available.
// test_socks5_success, test_socks5_trickle, test_socks5_err,
// test_socks5_auth_success, test_socks5_auth_fail, test_socks5_eager_err,
// test_socks5_premature_close: deferred until the SOCKS5 mode is available.
// No dedicated regular, local, or WireGuard test occurs in the pinned file;
// regular mode delegation is covered by TestExplicitProxyHandoff.

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(layertest.Timeout):
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		t.Fatalf("mode test stalled:\n%s", stack[:n])
		var zero T
		return zero
	}
}

func run(t *testing.T, l layer.Layer, c *layer.Context) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- l.Run(t.Context(), c) }()
	return await(t, done)
}

func newContext(t *testing.T, mode string) *layer.Context {
	t.Helper()
	opts := options.New()
	if err := opts.Add(t.Context(), "connection_strategy", options.TypeStr, "eager", "Server connection strategy."); err != nil {
		t.Fatal(err)
	}
	if err := opts.Add(t.Context(), "keep_host_header", options.TypeBool, false, "Preserve the original host."); err != nil {
		t.Fatal(err)
	}
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	client := connection.NewClient(connection.Address{}, connection.Address{}, 1)
	client.ProxyMode = mode
	return &layer.Context{
		Data:   &hookdata.Context{Client: client, Server: connection.NewServer(nil), Options: opts},
		Do:     manager.Do,
		Record: proxy.Record,
		Hooks:  &proxy.HookRunner{Manager: manager},
	}
}

func build(t *testing.T, c *layer.Context, kind hookdata.LayerKind) layer.Layer {
	t.Helper()
	l, err := layer.Build(t.Context(), c, hookdata.LayerStack{{Kind: kind}})
	if err != nil {
		t.Fatal(err)
	}
	if l.Kind() != kind || len(c.Data.Layers) != 1 || c.Data.Layers[0] != l {
		t.Fatal("top layer kind or published stack differs from descriptor")
	}
	return l
}

func TestReverseDestination(t *testing.T) {
	tests := map[string]struct {
		mode        string
		keep        bool
		wantAddress connection.Address
		wantSNI     string
	}{
		"http":            {"reverse:http://example.com", false, connection.Address{Host: "example.com", Port: 80}, "original.test"},
		"https":           {"reverse:https://example.com", false, connection.Address{Host: "example.com", Port: 443}, "example.com"},
		"https keep host": {"reverse:https://example.com", true, connection.Address{Host: "example.com", Port: 443}, "original.test"},
		"tls":             {"reverse:tls://example.com:9443", false, connection.Address{Host: "example.com", Port: 9443}, "example.com"},
		"tls keep host":   {"reverse:tls://example.com:9443", true, connection.Address{Host: "example.com", Port: 9443}, "original.test"},
		"tcp":             {"reverse:tcp://example.com:81", false, connection.Address{Host: "example.com", Port: 81}, "original.test"},
		"IPv6":            {"reverse:https://[::1]:8443", false, connection.Address{Host: "::1", Port: 8443}, "::1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := newContext(t, tt.mode)
			c.Data.Server.SNI = new("original.test")
			if err := c.Data.Options.Update(t.Context(), map[string]any{"keep_host_header": tt.keep}); err != nil {
				t.Fatal(err)
			}
			build(t, c, hookdata.LayerReverse)
			if diff := gocmp.Diff(&tt.wantAddress, c.Data.Server.Address); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(new(tt.wantSNI), c.Data.Server.SNI); diff != "" {
				t.Fatal(diff)
			}
			if c.Data.Server.TLS {
				t.Fatal("mode enabled TLS before the TLS child was selected")
			}
		})
	}
}

func TestReverseRejectsUnsupportedMode(t *testing.T) {
	tests := map[string]struct{ mode, want string }{
		"http3":      {"reverse:http3://example.com", "http3"},
		"quic":       {"reverse:quic://example.com:443", "quic"},
		"dns":        {"reverse:dns://example.com", "dns"},
		"wrong mode": {"regular", "reverse"},
		"malformed":  {"reverse:invalid://example.com", "invalid"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := newContext(t, tt.mode)
			_, err := layer.Build(t.Context(), c, hookdata.LayerStack{{Kind: hookdata.LayerReverse}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Build(%q) = %v; want error containing %q", tt.mode, err, tt.want)
			}
			if len(c.Data.Layers) != 0 || c.Data.Server.Address != nil {
				t.Fatal("failed construction published a layer or destination")
			}
		})
	}
}

type childLayer struct {
	run func(context.Context, *layer.Context) error
}

func (*childLayer) Kind() hookdata.LayerKind                          { return hookdata.LayerTCP }
func (l *childLayer) Run(ctx context.Context, c *layer.Context) error { return l.run(ctx, c) }

func TestExplicitProxyHandoff(t *testing.T) {
	tests := map[string]struct {
		mode string
		kind hookdata.LayerKind
	}{
		"regular":        {"regular", hookdata.LayerRegular},
		"upstream HTTP":  {"upstream:http://example.com", hookdata.LayerUpstream},
		"upstream HTTPS": {"upstream:https://example.com", hookdata.LayerUpstream},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := newContext(t, tt.mode)
			original := c.Data.Server.Clone()
			selected, ran := 0, 0
			wantErr := errors.New("child result")
			c.NextLayer = func(ctx context.Context, got *layer.Context) (layer.Layer, error) {
				selected++
				if ctx != t.Context() || got != c {
					t.Error("selector received a different context")
				}
				return &childLayer{run: func(ctx context.Context, got *layer.Context) error {
					ran++
					if ctx != t.Context() || got != c {
						t.Error("child received a different context")
					}
					return wantErr
				}}, nil
			}
			l := build(t, c, tt.kind)
			if selected != 0 {
				t.Fatal("constructor selected a child")
			}
			if err := run(t, l, c); !errors.Is(err, wantErr) {
				t.Fatalf("Run = %v", err)
			}
			if selected != 1 || ran != 1 {
				t.Fatalf("selected %d, ran %d", selected, ran)
			}
			if diff := gocmp.Diff(original, c.Data.Server); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// pool substitutes only the transport-pool boundary; its dialer uses real peers.
type pool struct {
	dial   layer.Dialer
	calls  int
	actual *connection.Server
}

func (p *pool) Open(ctx context.Context, srv *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	p.calls++
	if !opts.Reuse || opts.Setup != nil {
		return nil, nil, errors.New("mode did not request a reusable raw transport")
	}
	conn, err := p.dial(ctx, srv)
	if p.actual != nil {
		srv = p.actual
	}
	return conn, srv, err
}

func (*pool) Upgrade(context.Context, *connection.Server, func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) (layer.Conn, *connection.Server, error) {
	return nil, nil, errors.New("mode must not upgrade a transport")
}
func (*pool) Lookup(*connection.Server) (layer.Conn, bool) { return nil, false }

func TestReverseConnectOrdering(t *testing.T) {
	tests := map[string]struct {
		strategy  string
		transport connection.TransportProtocol
		noAddress bool
		wantCalls int
	}{
		"eager":                             {strategy: "eager", transport: connection.TCP, wantCalls: 1},
		"lazy":                              {strategy: "lazy", transport: connection.TCP},
		"datagram does not eagerly connect": {strategy: "eager", transport: connection.UDP},
		"unknown destination does not eagerly connect": {strategy: "eager", transport: connection.TCP, noAddress: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := newContext(t, "reverse:tls://example.com:443")
			if err := c.Data.Options.Set(t.Context(), "connection_strategy="+tt.strategy); err != nil {
				t.Fatal(err)
			}
			l := build(t, c, hookdata.LayerReverse)
			c.Data.Server.TransportProtocol = tt.transport
			if tt.noAddress {
				c.Data.Server.Address = nil
			}
			_, server := layertest.Pipe(t)
			actual := c.Data.Server.Clone()
			p := &pool{actual: actual, dial: func(ctx context.Context, srv *connection.Server) (layer.Conn, error) {
				// Acquiring the dispatch domain here proves Open runs outside it.
				if err := c.Do(ctx, func(context.Context) error { return nil }); err != nil {
					return nil, err
				}
				if srv != c.Data.Server {
					t.Error("pool received a different destination")
				}
				return server, nil
			}}
			c.Pool = p
			ran := false
			c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
				if p.calls != tt.wantCalls {
					t.Errorf("before any client read: opens=%d, want %d", p.calls, tt.wantCalls)
				}
				if tt.wantCalls != 0 && (c.Server == nil || c.Data.Server != actual) {
					t.Error("opened transport or actual metadata not published")
				}
				return &childLayer{run: func(context.Context, *layer.Context) error { ran = true; return nil }}, nil
			}
			if err := run(t, l, c); err != nil {
				t.Fatal(err)
			}
			if !ran {
				t.Fatal("selected child did not run")
			}
		})
	}
}

func TestReverseConnectFailure(t *testing.T) {
	c := newContext(t, "reverse:https://example.com")
	wantErr := errors.New("IPoAC packet dropped by cat")
	c.Pool = &pool{dial: func(context.Context, *connection.Server) (layer.Conn, error) { return nil, wantErr }}
	c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
		t.Error("selected a child after failed eager connect")
		return nil, nil
	}
	if err := run(t, build(t, c, hookdata.LayerReverse), c); !errors.Is(err, wantErr) {
		t.Fatalf("Run = %v", err)
	}
}

func TestSelectionFailure(t *testing.T) {
	tests := map[string]struct {
		mode string
		kind hookdata.LayerKind
	}{
		"regular":  {"regular", hookdata.LayerRegular},
		"reverse":  {"reverse:http://example.com", hookdata.LayerReverse},
		"upstream": {"upstream:https://example.com", hookdata.LayerUpstream},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := newContext(t, tt.mode)
			if err := c.Data.Options.Set(t.Context(), "connection_strategy=lazy"); err != nil {
				t.Fatal(err)
			}
			c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) { return nil, io.EOF }
			if err := run(t, build(t, c, tt.kind), c); !errors.Is(err, io.EOF) {
				t.Fatalf("Run = %v", err)
			}
		})
	}
}

func TestConformance(t *testing.T) {
	tests := map[string]struct {
		mode, strategy string
		kind           hookdata.LayerKind
	}{
		"regular":       {"regular", "eager", hookdata.LayerRegular},
		"upstream":      {"upstream:https://example.com", "eager", hookdata.LayerUpstream},
		"reverse eager": {"reverse:tcp://example.com:443", "eager", hookdata.LayerReverse},
		"reverse lazy":  {"reverse:tcp://example.com:443", "lazy", hookdata.LayerReverse},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			layertest.Conformance(t, func(t *testing.T) layertest.Session {
				clientPeer, client := layertest.Pipe(t)
				serverPeer, server := layertest.Pipe(t)
				c := newContext(t, tt.mode)
				c.Client = proxy.Record(client)
				sr := proxy.Record(server)
				if err := c.Data.Options.Set(t.Context(), "connection_strategy="+tt.strategy); err != nil {
					t.Fatal(err)
				}
				c.Pool = &pool{dial: func(context.Context, *connection.Server) (layer.Conn, error) { return sr, nil }}
				c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
					c.Client.StopRecording()
					if c.Server == nil {
						c.Server = sr
					}
					c.Server.StopRecording()
					return &childLayer{run: func(context.Context, *layer.Context) error {
						done := make(chan error, 2)
						relay := func(dst, src layer.Conn) {
							_, err := io.Copy(dst, src)
							if err == nil {
								err = dst.CloseWrite()
							}
							done <- err
						}
						go relay(c.Server, c.Client)
						go relay(c.Client, c.Server)
						return errors.Join(<-done, <-done)
					}}, nil
				}
				l := build(t, c, tt.kind)
				return layertest.Session{
					Client: clientPeer, Server: serverPeer, ClientInput: c.Client, ServerInput: sr,
					ClientData: []byte("hello server"), ServerData: []byte("hello client"),
					Run: func(ctx context.Context) error { return l.Run(ctx, c) },
				}
			})
		})
	}
}

// A net.Pipe deliberately has no CloseWrite; mode delegation must not require
// half-closing before handing its first buffered byte to the child.
type pipeConn struct{ net.Conn }

func (*pipeConn) CloseWrite() error { return errors.New("net.Pipe has no half-close") }

type nextHandler struct{ calls int }

func (h *nextHandler) NextLayer(_ context.Context, data *hookdata.NextLayer) error {
	h.calls++
	data.Layer = hookdata.LayerStack{{Kind: hookdata.LayerTCP}}
	return nil
}

func TestPipeReplay(t *testing.T) {
	peer, conn := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = conn.Close() })
	c := newContext(t, "regular")
	c.Client = proxy.Record(&pipeConn{conn})
	handler := new(nextHandler)
	if err := c.Hooks.(*proxy.HookRunner).Manager.Add(t.Context(), handler); err != nil {
		t.Fatal(err)
	}
	c.NextLayer = func(ctx context.Context, _ *layer.Context) (layer.Layer, error) {
		data, err := c.Client.Peek(1)
		if err != nil {
			return nil, err
		}
		decision := &hookdata.NextLayer{Context: c.Data, DataClient: data}
		if _, err := c.Hooks.Fire(ctx, addon.NextLayerHook{Data: decision}); err != nil {
			return nil, err
		}
		if err := c.Do(ctx, func(context.Context) error {
			if diff := gocmp.Diff(hookdata.LayerStack{{Kind: hookdata.LayerTCP}}, decision.Layer); diff != "" {
				t.Error(diff)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		c.Client.StopRecording()
		return &childLayer{run: func(context.Context, *layer.Context) error {
			data, err := io.ReadAll(c.Client)
			if diff := gocmp.Diff("hello", string(data)); diff != "" {
				t.Error(diff)
			}
			return err
		}}, nil
	}
	l := build(t, c, hookdata.LayerRegular)
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(peer, "hello"); _ = peer.Close(); done <- err }()
	if err := run(t, l, c); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if handler.calls != 1 {
		t.Fatalf("next_layer calls = %d, want 1", handler.calls)
	}
}
