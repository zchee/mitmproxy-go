// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package proxytest starts a complete in-process proxy for end-to-end tests.
//
// Start boots a master with the real proxyserver, nextlayer and tlsconfig
// addons on an ephemeral loopback listener with an isolated configuration
// directory, and returns once the running hook has fired, so the proxy CA
// exists and listeners accept connections. Origins are real sockets created
// with StartOrigin, StartEchoOrigin or StartTLSOrigin. A host under the .test
// top-level domain never resolves publicly: WithOrigin routes it to a local
// origin while the proxy keeps the original target metadata and SNI, and
// dialing an unmapped .test host fails.
//
// The certificate authorities of TLS origins registered with WithOrigin are
// trusted for upstream verification automatically; WithTrustedCA adds more.
// The Recorder's hook names are safe to read at any time, but its recorded
// arguments are live objects: read or mutate them only inside Master.Do.
package proxytest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/httplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
)

// Proxy is a running in-process proxy. Its listeners close when the test
// ends; accepted connections are canceled rather than joined.
type Proxy struct {
	// Addr is the first listener's address, in host:port form. It is empty
	// when the proxy was started with the server option disabled.
	Addr string
	// Master owns the dispatch domain; use Master.Do around hook state.
	Master *master.Master
	// ConfDir is the isolated configuration directory holding the CA files.
	ConfDir string
	// CA is the proxy's generated certificate authority.
	CA *x509.Certificate
	// CAPool contains CA, for client-side verification of the proxy.
	CAPool *x509.CertPool
	// Recorder records every hook dispatched by the master.
	Recorder *addontest.Recorder
	// Server is the proxyserver addon driving the listeners.
	Server *proxyserver.ProxyServer
}

// Origin is a local traffic destination used as the upstream of a proxy.
type Origin struct {
	// Addr is the origin's listen address, in host:port form.
	Addr string
	// CA is the origin's certificate authority; nil for a plaintext origin.
	CA *x509.Certificate
	// Leaf is the certificate the origin serves; nil for a plaintext origin.
	Leaf *x509.Certificate
}

type config struct {
	options map[string]any
	addons  []any
	origins map[string]*Origin
	trusted []*x509.Certificate
}

// Option configures Start.
type Option func(*config)

// WithOptions applies option values after the harness defaults, overriding
// them. Use it to select modes, timeouts and TLS options.
func WithOptions(values map[string]any) Option {
	return func(c *config) { maps.Copy(c.options, values) }
}

// WithAddons registers additional addons after the built-in ones.
func WithAddons(addons ...any) Option {
	return func(c *config) { c.addons = append(c.addons, addons...) }
}

// WithOrigin routes connections for host, which must end in ".test", to the
// origin. A TLS origin's CA becomes trusted for upstream verification.
func WithOrigin(host string, origin *Origin) Option {
	return func(c *config) { c.origins[strings.ToLower(strings.TrimSuffix(host, "."))] = origin }
}

// WithTrustedCA adds a certificate authority to the upstream trust bundle.
func WithTrustedCA(ca *x509.Certificate) Option {
	return func(c *config) { c.trusted = append(c.trusted, ca) }
}

// Start boots the proxy and returns once it accepts connections. Fatal
// configuration, listen and certificate errors fail the test immediately.
func Start(t testing.TB, opts ...Option) *Proxy {
	t.Helper()
	cfg := &config{options: make(map[string]any), origins: make(map[string]*Origin)}
	for _, opt := range opts {
		opt(cfg)
	}
	for host, origin := range cfg.origins {
		if !strings.HasSuffix(host, ".test") || origin == nil {
			t.Fatalf("proxytest: WithOrigin requires a .test host and non-nil origin: %q", host)
		}
	}
	confdir := t.TempDir()
	logger := slog.New(slog.DiscardHandler)
	m := master.New(master.Config{Logger: logger})
	lifetime, cancel := context.WithCancel(t.Context())
	t.Cleanup(func() {
		cancel()
		if err := m.Close(context.WithoutCancel(lifetime)); err != nil {
			t.Error(err)
		}
	})
	if err := m.Do(lifetime, func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"confdir": confdir, "listen_host": "127.0.0.1", "listen_port": new(0)})
	}); err != nil {
		t.Fatal(err)
	}
	recorder := &addontest.Recorder{}
	server, err := proxyserver.New(proxy.Config{
		Manager:     m.Addons,
		Options:     m.Options,
		Connections: new(proxy.Connections),
		Dialer:      originDialer(cfg.origins),
		Logger:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ready := &startup{ready: make(chan struct{})}
	addons := append([]any{server, nextlayer.New(m.Options), tlsconfig.New(m.Options), recorder}, cfg.addons...)
	addons = append(addons, ready)
	if err := m.Addons.Add(lifetime, addons...); err != nil {
		t.Fatal(err)
	}
	values := map[string]any{"confdir": confdir, "listen_host": "127.0.0.1", "listen_port": new(int)}
	if bundle := trustBundle(t, confdir, cfg); bundle != "" {
		values["ssl_verify_upstream_trusted_ca"] = &bundle
	}
	maps.Copy(values, cfg.options)
	if err := m.Do(lifetime, func(ctx context.Context) error { return m.Options.Update(ctx, values) }); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var runErr error
	go func() { runErr = m.Run(lifetime); close(done) }()
	t.Cleanup(func() {
		cancel()
		wait(t, done, "master shutdown")
		if runErr != nil {
			t.Error(runErr)
		}
	})
	select {
	case <-ready.ready:
	case <-done:
		t.Fatalf("proxytest: master stopped before running: %v", runErr)
	case <-time.After(30 * time.Second):
		failHang(t, "master startup")
	}
	// Cross the dispatch barrier after the final running handler returned.
	if err := m.Do(lifetime, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	confdir = m.Options.Str("confdir")
	ca := readCA(t, confdir)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	var addr string
	if addrs := server.ListenAddrs(); len(addrs) > 0 {
		addr = addrs[0].String()
	} else if m.Options.Bool("server") {
		t.Fatal("proxytest: no listening address")
	}
	return &Proxy{Addr: addr, Master: m, ConfDir: confdir, CA: ca, CAPool: pool, Recorder: recorder, Server: server}
}

type startup struct{ ready chan struct{} }

// Running signals that the proxy master has completed startup.
func (s *startup) Running(context.Context) error { close(s.ready); return nil }

func wait(t testing.TB, done <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		failHang(t, operation)
	}
}

func failHang(t testing.TB, operation string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	t.Fatalf("proxytest: %s hung\n%s", operation, buf[:runtime.Stack(buf, true)])
}

func trustBundle(t testing.TB, confdir string, cfg *config) string {
	t.Helper()
	seen := make(map[*x509.Certificate]bool)
	var bundle []byte
	add := func(ca *x509.Certificate) {
		if ca == nil || seen[ca] {
			return
		}
		seen[ca] = true
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	for _, origin := range cfg.origins {
		add(origin.CA)
	}
	for _, ca := range cfg.trusted {
		add(ca)
	}
	if bundle == nil {
		return ""
	}
	path := filepath.Join(confdir, "proxytest-trusted-ca.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readCA(t testing.TB, confdir string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(confdir, options.ConfBasename+"-ca-cert.pem")) //nolint:gosec // The test chooses the configuration directory holding its generated public CA.
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("proxytest: CA file holds no PEM block")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func originDialer(origins map[string]*Origin) layer.Dialer {
	return func(ctx context.Context, server *connection.Server) (layer.Conn, error) {
		if server.Address == nil || server.Address.Host == "" {
			return nil, errors.New("proxytest: server address unknown")
		}
		if server.TransportProtocol != connection.TCP {
			return nil, fmt.Errorf("proxytest: unsupported transport %q", server.TransportProtocol)
		}
		target := server.Address.String()
		if host := strings.ToLower(strings.TrimSuffix(server.Address.Host, ".")); strings.HasSuffix(host, ".test") {
			origin, ok := origins[host]
			if !ok {
				return nil, fmt.Errorf("proxytest: no origin mapped for %s", host)
			}
			target = origin.Addr
		}
		dialer := new(net.Dialer)
		if server.Sockname != nil {
			local := &net.TCPAddr{Port: server.Sockname.Port}
			if server.Sockname.Host != "" {
				ip, err := netip.ParseAddr(server.Sockname.Host)
				if err != nil {
					return nil, fmt.Errorf("proxytest: invalid source address %q: %w", server.Sockname.Host, err)
				}
				local.IP, local.Zone = ip.AsSlice(), ip.Zone()
			}
			if server.Sockname.Scope != nil && server.Sockname.Scope.ScopeID != 0 {
				local.Zone = strconv.FormatUint(uint64(server.Sockname.Scope.ScopeID), 10)
			}
			dialer.LocalAddr = local
		}
		conn, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	}
}

// StartOrigin starts a plaintext origin that runs handler once per accepted
// connection on its own goroutine. The handler owns the connection; the
// origin closes it afterwards. The origin closes when the test ends, after
// the running handlers have returned.
func StartOrigin(t testing.TB, handler func(net.Conn)) *Origin {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(t, listener, handler)
	return &Origin{Addr: listener.Addr().String()}
}

// StartEchoOrigin starts a plaintext origin that writes every received byte
// back to its sender.
func StartEchoOrigin(t testing.TB) *Origin {
	t.Helper()
	return StartOrigin(t, echo)
}

func echo(conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// StartTLSOrigin starts a TLS origin with its own certificate authority and a
// leaf covering names, which may be DNS names or IP addresses. A nil handler
// echoes. The handler receives the connection after the TLS handshake
// configuration is attached; the handshake itself completes on first use.
func StartTLSOrigin(t testing.TB, names []string, handler func(net.Conn)) *Origin {
	t.Helper()
	if len(names) == 0 {
		t.Fatal("proxytest: StartTLSOrigin requires at least one name")
	}
	if handler == nil {
		handler = echo
	}
	caKey, ca, err := certs.CreateCA("mitmproxy-go proxytest", "proxytest origin CA", 2048)
	if err != nil {
		t.Fatal(err)
	}
	sans := make([]certs.GeneralName, 0, len(names))
	for _, name := range names {
		if ip, err := netip.ParseAddr(name); err == nil {
			sans = append(sans, certs.IPAddress(ip))
		} else {
			sans = append(sans, certs.DNSName(name))
		}
	}
	leaf, err := certs.DummyCert(caKey, ca, names[0], sans, "", "")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw, ca.X509().Raw}, PrivateKey: caKey, Leaf: leaf.X509()}},
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(t, listener, func(conn net.Conn) { handler(tls.Server(conn, tlsConfig)) })
	return &Origin{Addr: listener.Addr().String(), CA: ca.X509(), Leaf: leaf.X509()}
}

func serve(t testing.TB, listener net.Listener, handler func(net.Conn)) {
	t.Helper()
	var mu sync.Mutex
	closed := false
	accepted := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				continue
			}
			accepted[conn] = struct{}{}
			mu.Unlock()
			workers.Go(func() {
				defer func() {
					_ = conn.Close()
					mu.Lock()
					delete(accepted, conn)
					mu.Unlock()
				}()
				handler(conn)
			})
		}
	})
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		closed = true
		for conn := range accepted {
			_ = conn.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		wait(t, done, "origin shutdown")
	})
}
