// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/internal/tlsnames"
	"github.com/zchee/mitmproxy-go/options"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
)

// tlsObserver is a real addon that answers the server-side TLS hooks: it
// supplies config on tls_start_server and records every event in dispatch
// order. check, when set, runs under the dispatch hold of each hook.
type tlsObserver struct {
	config *tls.Config
	check  func(event string, data *hookdata.TLS)
	events []string
}

func (o *tlsObserver) handle(event string, data *hookdata.TLS) error {
	o.events = append(o.events, event)
	if o.check != nil {
		o.check(event, data)
	}
	return nil
}

func (o *tlsObserver) TLSStartServer(_ context.Context, data *hookdata.TLS) error {
	data.Config = o.config
	return o.handle("tls_start_server", data)
}

func (o *tlsObserver) TLSEstablishedServer(_ context.Context, data *hookdata.TLS) error {
	return o.handle("tls_established_server", data)
}

func (o *tlsObserver) TLSFailedServer(_ context.Context, data *hookdata.TLS) error {
	return o.handle("tls_failed_server", data)
}

// pipePool hands out one prepared transport and honors the setup contract:
// setup runs on Open and Upgrade, and a failed setup closes the transport.
type pipePool struct {
	conn        layer.Conn
	setups      int
	beforeOpen  func(*connection.Server)
	beforeSetup func(context.Context, layer.Conn) error
	reusable    layer.Conn
	actual      *connection.Server
}

func (p *pipePool) Open(ctx context.Context, srv *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	if p.beforeOpen != nil {
		p.beforeOpen(srv)
	}
	if opts.Reuse && srv == p.actual && p.reusable != nil {
		return p.reusable, p.actual, nil
	}
	conn := p.conn
	if p.beforeSetup != nil {
		if err := p.beforeSetup(ctx, conn); err != nil {
			return nil, nil, err
		}
	}
	if opts.Setup != nil {
		p.setups++
		wrapped, err := opts.Setup(ctx, conn, srv)
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		conn = wrapped
	}
	p.reusable, p.actual = conn, srv
	return conn, srv, nil
}

func (p *pipePool) Upgrade(ctx context.Context, srv *connection.Server, setup func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) (layer.Conn, *connection.Server, error) {
	p.setups++
	wrapped, err := setup(ctx, p.conn, srv)
	if err != nil {
		_ = p.conn.Close()
		return nil, nil, err
	}
	p.reusable, p.actual = wrapped, srv
	return wrapped, srv, nil
}

func (p *pipePool) Lookup(*connection.Server) (layer.Conn, bool) { return nil, false }

// Retire is a no-op for the single-transport test adapter.
func (*pipePool) Retire(*connection.Server) {}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// innerLayer is a real child layer whose behavior each test supplies.
type innerLayer struct {
	kind hookdata.LayerKind
	run  func(context.Context, *layer.Context) error
}

func (l innerLayer) Kind() hookdata.LayerKind { return l.kind }

func (l innerLayer) Run(ctx context.Context, c *layer.Context) error { return l.run(ctx, c) }

type serverSession struct {
	c          *layer.Context
	manager    *addon.Manager
	observed   *tlsObserver
	logs       *lockedBuffer
	pool       *pipePool
	peer       layer.Conn
	raw        layer.Conn
	clientPeer layer.Conn
}

func newServerSession(t *testing.T, observed *tlsObserver) *serverSession {
	t.Helper()
	clientPeer, clientInput := layertest.Pipe(t)
	raw, peer := layertest.Pipe(t)
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), observed); err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	pool := &pipePool{conn: raw}
	return &serverSession{
		manager: manager, observed: observed, logs: logs, pool: pool,
		peer: peer, raw: raw, clientPeer: clientPeer,
		c: &layer.Context{
			Data: &hookdata.Context{
				Client: connection.NewClient(connection.Address{}, connection.Address{}, 1),
				Server: connection.NewServer(nil), Options: options.New(),
			},
			Client: proxy.Record(clientInput), Record: proxy.Record,
			Hooks: &proxy.HookRunner{Manager: manager}, Do: manager.Do,
			Pool: pool, Logger: slog.New(slog.NewTextHandler(logs, nil)),
		},
	}
}

func (s *serverSession) run(t *testing.T, child layer.Layer) error {
	t.Helper()
	l := &serverTLS{child: child}
	done := make(chan error, 1)
	go func() { done <- l.Run(t.Context(), s.c) }()
	return await(t, done)
}

// server reads the server metadata under the dispatch lock after a run.
func (s *serverSession) server(t *testing.T) connection.Server {
	t.Helper()
	var srv connection.Server
	if err := s.manager.Do(t.Context(), func(context.Context) error {
		srv = *s.c.Data.Server
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return srv
}

// openServer opens the context's server through the pool the layer provided.
func openServer(ctx context.Context, c *layer.Context) (layer.Conn, error) {
	var metadata *connection.Server
	if err := c.Do(ctx, func(context.Context) error {
		metadata = c.Data.Server
		return nil
	}); err != nil {
		return nil, err
	}
	conn, _, err := c.Pool.Open(ctx, metadata, layer.OpenOptions{})
	return conn, err
}

// exchangeChild opens the server and performs one ping/pong exchange over
// whatever transport the pool returned.
func exchangeChild(kind hookdata.LayerKind) innerLayer {
	return innerLayer{kind: kind, run: func(ctx context.Context, c *layer.Context) error {
		conn, err := openServer(ctx, c)
		if err != nil {
			return err
		}
		return pingPong(conn)
	}}
}

func pingPong(conn layer.Conn) error {
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	reply := make([]byte, len("pong"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != "pong" {
		return fmt.Errorf("reply = %q, want %q", reply, "pong")
	}
	return nil
}

// pongPeer completes the server side of the TLS handshake and answers one
// ping with one pong.
func pongPeer(t *testing.T, conn layer.Conn, config *tls.Config) <-chan error {
	t.Helper()
	ctx := t.Context()
	done := make(chan error, 1)
	go func() {
		tc := tls.Server(conn, config)
		if err := tc.HandshakeContext(ctx); err != nil {
			done <- err
			return
		}
		request := make([]byte, len("ping"))
		if _, err := io.ReadFull(tc, request); err != nil {
			done <- err
			return
		}
		if string(request) != "ping" {
			done <- fmt.Errorf("request = %q, want %q", request, "ping")
			return
		}
		_, err := tc.Write([]byte("pong"))
		done <- err
	}()
	return done
}

// Upstream TestServerTLS.test_simple: hooks fire in order, the handshake
// metadata is published, and application data crosses the established TLS
// connection, through an explicit child and through the next-layer loop.
func TestServerTLSEstablish(t *testing.T) {
	tests := map[string]struct {
		nextProtos []string
		wantALPN   []byte
		viaNext    bool
	}{
		"negotiated alpn": {nextProtos: []string{"h2"}, wantALPN: []byte("h2")},
		"no alpn":         {wantALPN: []byte{}},
		"next handover":   {wantALPN: []byte{}, viaNext: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConfig, clientConfig := tlsConfigs(t)
			serverConfig.NextProtos = tt.nextProtos
			clientConfig.NextProtos = tt.nextProtos
			observed := &tlsObserver{config: clientConfig, check: func(event string, data *hookdata.TLS) {
				if !data.IsServer() {
					t.Errorf("%s: IsServer() = false", event)
				}
				if event == "tls_established_server" && !data.Conn.TLSEstablished() {
					t.Errorf("%s: handshake timestamp not yet published", event)
				}
			}}
			s := newServerSession(t, observed)
			peer := pongPeer(t, s.peer, serverConfig)
			child := exchangeChild("test-exchange")
			var run layer.Layer = child
			if tt.viaNext {
				run = nil
				s.c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
					return child, nil
				}
			}
			if err := s.run(t, run); err != nil {
				t.Fatal(err)
			}
			if err := await(t, peer); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"tls_start_server", "tls_established_server"}, s.observed.events); diff != "" {
				t.Errorf("events (-want +got):\n%s", diff)
			}
			srv := s.server(t)
			if !srv.TLS {
				t.Error("Server.TLS = false")
			}
			if srv.TLSVersion != connection.TLSv1_3 {
				t.Errorf("TLSVersion = %q, want %q", srv.TLSVersion, connection.TLSv1_3)
			}
			if srv.Cipher == nil {
				t.Error("Cipher = nil")
			} else if _, ok := tlsnames.SuiteID(*srv.Cipher); !ok {
				t.Errorf("Cipher = %q, not an OpenSSL suite name", *srv.Cipher)
			}
			if srv.ALPN == nil || !bytes.Equal(srv.ALPN, tt.wantALPN) {
				t.Errorf("ALPN = %v, want non-nil %q", srv.ALPN, tt.wantALPN)
			}
			if srv.TimestampTLSSetup == nil || *srv.TimestampTLSSetup <= 0 {
				t.Errorf("TimestampTLSSetup = %v", srv.TimestampTLSSetup)
			}
			if len(srv.CertificateList) != 1 {
				t.Fatalf("CertificateList length = %d", len(srv.CertificateList))
			}
			block, rest := pem.Decode(srv.CertificateList[0])
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				t.Fatalf("CertificateList[0] is not a single CERTIFICATE block: %q", srv.CertificateList[0])
			}
		})
	}
}

// Upstream TestServerTLS.test_not_connected: entering the layer neither
// dials nor handshakes while the child leaves the server closed, but the
// connection is already marked as destined for TLS.
func TestServerTLSNotConnected(t *testing.T) {
	s := newServerSession(t, &tlsObserver{})
	err := s.run(t, innerLayer{kind: "test-idle", run: func(context.Context, *layer.Context) error {
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if s.pool.setups != 0 {
		t.Errorf("setup ran %d times without a server connection", s.pool.setups)
	}
	if len(s.observed.events) != 0 {
		t.Errorf("events = %v, want none", s.observed.events)
	}
	if srv := s.server(t); !srv.TLS {
		t.Error("Server.TLS = false")
	}
}

// Upstream start_tls without a configuration: the connection fails with the
// exact diagnostic and no handshake hooks run.
func TestServerTLSNilConfig(t *testing.T) {
	s := newServerSession(t, &tlsObserver{})
	err := s.run(t, exchangeChild("test-exchange"))
	if err == nil {
		t.Fatal("run succeeded without a TLS configuration")
	}
	if diff := gocmp.Diff([]string{"tls_start_server"}, s.observed.events); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
	if logs := s.logs.String(); !strings.Contains(logs, "No TLS context was provided, failing connection.") {
		t.Errorf("logs = %q, want the missing-context diagnostic", logs)
	}
}

// Upstream TestServerTLS.test_untrusted_cert, test_remote_speaks_no_tls and
// test_unsupported_protocol: each handshake failure is explained, recorded
// on the connection, fired as tls_failed_server and returned to the opener.
func TestServerTLSHandshakeFailure(t *testing.T) {
	tests := map[string]struct {
		configure func(serverConfig, clientConfig *tls.Config)
		peer      func(t *testing.T, conn layer.Conn, config *tls.Config) <-chan error
		wantErr   string
	}{
		"untrusted certificate": {
			configure: func(_, clientConfig *tls.Config) { clientConfig.ServerName = "wrong.host" },
			peer: func(t *testing.T, conn layer.Conn, config *tls.Config) <-chan error {
				done := make(chan error, 1)
				ctx := t.Context()
				go func() {
					// The proxy rejects the certificate, so this handshake fails too.
					_ = tls.Server(conn, config).HandshakeContext(ctx)
					done <- nil
				}()
				return done
			},
			wantErr: "Certificate verify failed: ",
		},
		"remote speaks no tls": {
			configure: func(_, _ *tls.Config) {},
			peer: func(t *testing.T, conn layer.Conn, _ *tls.Config) <-chan error {
				done := make(chan error, 1)
				go func() {
					header := make([]byte, 5)
					if _, err := io.ReadFull(conn, header); err != nil {
						done <- err
						return
					}
					_, err := conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
					done <- err
				}()
				return done
			},
			wantErr: "The remote server does not speak TLS.",
		},
		"unsupported protocol": {
			configure: func(serverConfig, clientConfig *tls.Config) {
				serverConfig.MaxVersion = tls.VersionTLS12
				clientConfig.MinVersion = tls.VersionTLS13
			},
			peer: func(t *testing.T, conn layer.Conn, config *tls.Config) <-chan error {
				done := make(chan error, 1)
				ctx := t.Context()
				go func() {
					// No shared version: this side fails with its own alert.
					_ = tls.Server(conn, config).HandshakeContext(ctx)
					done <- nil
				}()
				return done
			},
			wantErr: "The remote server and mitmproxy cannot agree on a TLS version to use.",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConfig, clientConfig := tlsConfigs(t)
			tt.configure(serverConfig, clientConfig)
			observed := &tlsObserver{config: clientConfig, check: func(event string, data *hookdata.TLS) {
				if event == "tls_failed_server" && data.Conn.Error == nil {
					t.Error("tls_failed_server fired before the error was recorded")
				}
			}}
			s := newServerSession(t, observed)
			peer := tt.peer(t, s.peer, serverConfig)
			err := s.run(t, exchangeChild("test-exchange"))
			if err == nil {
				t.Fatal("run succeeded past a failing handshake")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %q, want %q", err, tt.wantErr)
			}
			if err := await(t, peer); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"tls_start_server", "tls_failed_server"}, s.observed.events); diff != "" {
				t.Errorf("events (-want +got):\n%s", diff)
			}
			srv := s.server(t)
			if srv.Error == nil {
				t.Fatal("Server.Error = nil")
			}
			if !strings.Contains(*srv.Error, tt.wantErr) {
				t.Errorf("Server.Error = %q, want %q", *srv.Error, tt.wantErr)
			}
			if srv.TimestampTLSSetup != nil {
				t.Errorf("TimestampTLSSetup = %v after a failed handshake", *srv.TimestampTLSSetup)
			}
			if logs := s.logs.String(); !strings.Contains(logs, "Server TLS handshake failed.") {
				t.Errorf("logs = %q, want the handshake warning", logs)
			}
		})
	}
}

// A server transport that is already open when the layer starts is upgraded
// to TLS before the child runs, through the pool's exactly-once Upgrade.
func TestServerTLSEagerAtStart(t *testing.T) {
	serverConfig, clientConfig := tlsConfigs(t)
	s := newServerSession(t, &tlsObserver{config: clientConfig})
	original := proxy.Record(s.raw)
	s.c.Server = original
	peer := pongPeer(t, s.peer, serverConfig)
	err := s.run(t, innerLayer{kind: "test-established", run: func(_ context.Context, c *layer.Context) error {
		if c.Server == original {
			t.Error("child still sees the raw transport")
		}
		c.Server.StopRecording()
		return pingPong(c.Server)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := await(t, peer); err != nil {
		t.Fatal(err)
	}
	if s.pool.setups != 1 {
		t.Errorf("setup ran %d times, want 1", s.pool.setups)
	}
	if diff := gocmp.Diff([]string{"tls_start_server", "tls_established_server"}, s.observed.events); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
}

// A connection the child opens to another server than the context's fires
// the hooks against that server's own metadata, leaving the context's
// server in place for its handlers.
func TestServerTLSAlternateTarget(t *testing.T) {
	serverConfig, clientConfig := tlsConfigs(t)
	target := connection.NewServer(nil)
	observed := &tlsObserver{config: clientConfig}
	s := newServerSession(t, observed)
	s.pool.beforeOpen = func(srv *connection.Server) {
		if err := s.manager.Do(t.Context(), func(context.Context) error {
			if !srv.TLS {
				t.Error("pool key constructed before target.TLS was set")
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	}
	observed.check = func(event string, data *hookdata.TLS) {
		if data.Conn != &target.Connection {
			t.Errorf("%s: hook is not about the opened target", event)
		}
		if !data.IsServer() {
			t.Errorf("%s: IsServer() = false", event)
		}
		if data.Context == s.c.Data || data.Context.Server != target {
			t.Errorf("%s: hook context does not single out the target", event)
		}
	}
	peer := pongPeer(t, s.peer, serverConfig)
	err := s.run(t, innerLayer{kind: "test-target", run: func(ctx context.Context, c *layer.Context) error {
		conn, _, err := c.Pool.Open(ctx, target, layer.OpenOptions{})
		if err != nil {
			return err
		}
		return pingPong(conn)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := await(t, peer); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"tls_start_server", "tls_established_server"}, s.observed.events); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
	if err := s.manager.Do(t.Context(), func(context.Context) error {
		if s.c.Data.Server == target {
			return fmt.Errorf("context server was replaced by the target")
		}
		if !target.TLS || !target.TLSEstablished() {
			return fmt.Errorf("target metadata not published: tls=%t established=%t", target.TLS, target.TLSEstablished())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The layer registers itself for next-layer stacks and nests a child layer.
func TestServerTLSBuild(t *testing.T) {
	s := newServerSession(t, &tlsObserver{})
	l, err := layer.Build(t.Context(), s.c, hookdata.LayerStack{{Kind: hookdata.LayerServerTLS}, {Kind: hookdata.LayerTCP}})
	if err != nil {
		t.Fatal(err)
	}
	if l.Kind() != hookdata.LayerServerTLS {
		t.Fatalf("Kind() = %v", l.Kind())
	}
	if len(s.c.Data.Layers) != 2 {
		t.Fatalf("published layers = %d, want 2", len(s.c.Data.Layers))
	}
}
