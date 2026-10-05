// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// The tests port test/mitmproxy/addons/test_tlsconfig.py. Each upstream test
// maps to a Go test, or is listed here with the reason it has no port:
//
//	test_alpn_select_callback                         -> TestALPNSelect
//	TestTlsConfig.test_configure                      -> TestConfigureCerts and TestConfigureECDHCurve
//	TestTlsConfig.test_configure_tls_version          -> TestConfigureTLSVersionWarnings
//	TestTlsConfig.test_configure_ciphers              -> TestConfigureCiphers: the @SECLEVEL warnings are not ported, because the cipher options accept only exact OpenSSL suite names, so "ALL" and "@SECLEVEL=0" fail with an OptionsError instead (docs/compat.md)
//	TestTlsConfig.test_get_cert                       -> TestGetCert
//	TestTlsConfig.test_tls_clienthello                -> TestTLSClientHello
//	TestTlsConfig.test_tls_start_client               -> TestTLSStartClient
//	TestTlsConfig.test_quic_start_client              -> not applicable: QUIC is not implemented
//	TestTlsConfig.test_tls_start_server_cannot_verify -> TestTLSStartServer/"error: empty sni opts out of verification"
//	TestTlsConfig.test_tls_start_server_verify_failed -> TestTLSStartServer/"error: handshake with an untrusted server fails"
//	TestTlsConfig.test_tls_start_server_verify_ok     -> TestTLSStartServer/"success: verified handshake by dns name" and "success: verified handshake by ip address"
//	TestTlsConfig.test_quic_start_server_verify_ok    -> not applicable: QUIC is not implemented
//	TestTlsConfig.test_tls_start_server_insecure      -> TestTLSStartServer/"success: insecure skips verification"
//	TestTlsConfig.test_quic_start_server_insecure     -> not applicable: QUIC is not implemented
//	TestTlsConfig.test_alpn_selection                 -> TestServerALPNOffers and TestTLSStartServer/"success: alpn offers mirror the client"
//	TestTlsConfig.test_no_h2_proxy                    -> TestNoH2Proxy: the forced protocol is observed on the configuration's NextProtos instead of pyOpenSSL app data
//	TestTlsConfig.test_client_cert_file               -> TestTLSStartServer/"success: client certificate from a file" and "success: client certificate from a directory"
//	TestTlsConfig.test_ca_expired                     -> TestCAExpired: an expired CA is written to disk instead of monkeypatching has_expired
//	TestTlsConfig.test_crl_substitution               -> TestCRLSubstitution
//	TestTlsConfig.test_crl_request                    -> TestCRLRequest
//	test_default_ciphers                              -> not applicable: without a ciphers option the configurations keep the crypto/tls default suites instead of upstream's OpenSSL cipher string (docs/compat.md)
package tlsconfig

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/tlsnames"
	"github.com/zchee/mitmproxy-go/options"
)

func newTLSConfig(t *testing.T) (*TLSConfig, *addon.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	tc := New(opts)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(func() {
		if err := m.Clear(t.Context()); err != nil {
			t.Error(err)
		}
		m.Close()
	})
	if err := m.Add(t.Context(), tc); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), tc.Running); err != nil {
		t.Fatal(err)
	}
	return tc, m, opts
}

func configure(t *testing.T, m *addon.Manager, opts *options.Manager, values map[string]any) error {
	t.Helper()
	return m.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, values) })
}

// testContext builds the connection context upstream's _ctx builds: a client
// from ("client", 1234) to ("127.0.0.1", 8080) and a server without an
// address.
func testContext(opts *options.Manager) *hookdata.Context {
	client := connection.NewClient(connection.Address{Host: "client", Port: 1234}, connection.Address{Host: "127.0.0.1", Port: 8080}, 1605699329)
	return &hookdata.Context{Client: client, Server: connection.NewServer(nil), Options: opts}
}

// logRecorder captures slog output; tests that install it must not run in
// parallel.
type logRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *logRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	return nil
}

func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *logRecorder) WithGroup(string) slog.Handler { return r }

func (r *logRecorder) text(t *testing.T) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, rec := range r.records {
		b.WriteString(rec.Message)
		b.WriteString("\n")
	}
	return b.String()
}

func (r *logRecorder) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = nil
}

func captureLogs(t *testing.T) *logRecorder {
	t.Helper()
	rec := &logRecorder{}
	previous := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return rec
}

// TestOptions checks that Load registers exactly the options upstream's
// tlsconfig addon registers, with upstream's types, defaults and help texts
// (from testdata/options-upstream.txt), and the TLS version choices.
func TestOptions(t *testing.T) {
	t.Parallel()
	_, _, opts := newTLSConfig(t)

	names := []string{
		"tls_version_client_min", "tls_version_client_max",
		"tls_version_server_min", "tls_version_server_max",
		"tls_ecdh_curve_client", "tls_ecdh_curve_server",
		"request_client_cert", "ciphers_client", "ciphers_server",
	}

	upstream := make(map[string][]string)
	for line := range strings.SplitSeq(strings.TrimSuffix(string(testutil.Fixture(t, "options-upstream.txt")), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("options-upstream.txt: %d tab-separated fields, want 4", len(fields))
		}
		upstream[fields[0]] = fields[1:]
	}

	for _, name := range names {
		row, ok := upstream[name]
		if !ok {
			t.Fatalf("option %s is missing from testdata/options-upstream.txt", name)
		}
		o, ok := opts.Lookup(name)
		if !ok {
			t.Errorf("option %s is not registered", name)
			continue
		}
		if got, want := o.Type().String(), row[0]; got != want {
			t.Errorf("option %s type = %s, want %s", name, got, want)
		}
		var def string
		switch v := o.Default().(type) {
		case nil:
			def = "null"
		case *string:
			if v == nil {
				def = "null"
			} else {
				def = `"` + *v + `"`
			}
		case string:
			def = `"` + v + `"`
		case bool:
			if v {
				def = "true"
			} else {
				def = "false"
			}
		default:
			t.Fatalf("option %s has unexpected default type %T", name, v)
		}
		if def != row[1] {
			t.Errorf("option %s default = %s, want %s", name, def, row[1])
		}
		if got, want := o.Help(), row[2]; got != want {
			t.Errorf("option %s help = %q, want %q", name, got, want)
		}
		wantChoices := []string(nil)
		if strings.HasPrefix(name, "tls_version_") {
			wantChoices = []string{"UNBOUNDED", "SSL3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}
		}
		if diff := gocmp.Diff(wantChoices, o.Choices()); diff != "" {
			t.Errorf("option %s choices mismatch (-want +got):\n%s", name, diff)
		}
	}
}

// Upstream TestTlsConfig.test_configure: invalid certificate specifications
// reject the option update instead of leaving a partly configured store.
func TestConfigureCerts(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		spec    string
		wantErr string
	}{
		"error: missing certificate":     {spec: "*=nonexistent", wantErr: "Certificate file does not exist"},
		"error: key without certificate": {spec: testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-leaf.key"), wantErr: "Invalid certificate format"},
		"success: certificate and key":   {spec: testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-leaf.pem")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, m, opts := newTLSConfig(t)
			old := tc.store
			err := configure(t, m, opts, map[string]any{"certs": []string{tt.spec}})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("configure certs error = %v, want %q", err, tt.wantErr)
				}
				if _, ok := errors.AsType[*options.OptionsError](err); !ok {
					t.Errorf("configure error = %T, want OptionsError", err)
				}
				if tc.store == nil || old == nil {
					t.Error("rejected configuration lost the previous store")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			entry, err := tc.store.GetCert("example.mitmproxy.org", nil, "", "")
			if err != nil {
				t.Fatal(err)
			}
			if entry.Cert.CN() != "example.mitmproxy.org" {
				t.Fatal(entry.Cert.CN())
			}
		})
	}
}

// Upstream TestTlsConfig.test_configure (the ECDH branch).
func TestConfigureECDHCurve(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		option  string
		value   string
		wantErr bool
	}{
		"error: invalid client curve":  {option: "tls_ecdh_curve_client", value: "invalid", wantErr: true},
		"error: invalid server curve":  {option: "tls_ecdh_curve_server", value: "invalid", wantErr: true},
		"error: unmappable curve":      {option: "tls_ecdh_curve_client", value: "secp256k1", wantErr: true},
		"success: valid client curve":  {option: "tls_ecdh_curve_client", value: "secp256r1"},
		"success: valid server curve":  {option: "tls_ecdh_curve_server", value: "secp384r1"},
		"success: valid 521 bit curve": {option: "tls_ecdh_curve_client", value: "secp521r1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, m, opts := newTLSConfig(t)
			err := configure(t, m, opts, map[string]any{tt.option: &tt.value})
			if !tt.wantErr {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatalf("configure accepted %s=%q", tt.option, tt.value)
			}
			if _, ok := errors.AsType[*options.OptionsError](err); !ok {
				t.Errorf("configure error is %T, want *options.OptionsError", err)
			}
			if want := "Invalid ECDH curve"; !strings.Contains(err.Error(), want) {
				t.Errorf("configure error %q does not contain %q", err, want)
			}
		})
	}
}

// Upstream TestTlsConfig.test_configure_tls_version, with crypto/tls in the
// message where upstream names the OpenSSL build (docs/compat.md).
func TestConfigureTLSVersionWarnings(t *testing.T) {
	logs := captureLogs(t)
	_, m, opts := newTLSConfig(t)

	for _, option := range []string{"tls_version_client_min", "tls_version_client_max", "tls_version_server_min", "tls_version_server_max"} {
		logs.clear()
		if err := configure(t, m, opts, map[string]any{option: "SSL3"}); err != nil {
			t.Fatal(err)
		}
		if want := option + " has been set to SSL3, which is not supported by crypto/tls."; !strings.Contains(logs.text(t), want) {
			t.Errorf("configure(%s=SSL3) logged %q, want it to contain %q", option, logs.text(t), want)
		}
	}

	logs.clear()
	if err := configure(t, m, opts, map[string]any{"tls_version_client_min": "UNBOUNDED"}); err != nil {
		t.Fatal(err)
	}
	if want := "tls_version_client_min has been set to UNBOUNDED. Note that crypto/tls only supports the following TLS versions"; !strings.Contains(logs.text(t), want) {
		t.Errorf("configure(tls_version_client_min=UNBOUNDED) logged %q, want it to contain %q", logs.text(t), want)
	}

	logs.clear()
	if err := configure(t, m, opts, map[string]any{"tls_version_client_max": "UNBOUNDED"}); err != nil {
		t.Fatal(err)
	}
	if text := logs.text(t); text != "" {
		t.Errorf("configure(tls_version_client_max=UNBOUNDED) logged %q, want nothing", text)
	}
}

// Upstream TestTlsConfig.test_configure_ciphers, adapted to the exact-name
// rule: upstream warns about a missing @SECLEVEL, here every value that is
// not a colon-separated list of exact OpenSSL suite names is rejected
// (docs/compat.md).
func TestConfigureCiphers(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		option  string
		value   string
		wantErr string
	}{
		"success: exact client names": {option: "ciphers_client", value: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"},
		"success: exact server name":  {option: "ciphers_server", value: "ECDHE-ECDSA-AES128-GCM-SHA256"},
		"error: client alias":         {option: "ciphers_client", value: "ALL", wantErr: `"ALL"`},
		"error: server alias":         {option: "ciphers_server", value: "ALL", wantErr: `"ALL"`},
		"error: cipher string":        {option: "ciphers_client", value: "HIGH:!aNULL", wantErr: `"HIGH"`},
		"error: seclevel keyword":     {option: "ciphers_client", value: "@SECLEVEL=0:ALL", wantErr: `"@SECLEVEL=0"`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, m, opts := newTLSConfig(t)
			err := configure(t, m, opts, map[string]any{tt.option: &tt.value})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatalf("configure accepted %s=%q", tt.option, tt.value)
			}
			if _, ok := errors.AsType[*options.OptionsError](err); !ok {
				t.Errorf("configure error is %T, want *options.OptionsError", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), tt.option) {
				t.Errorf("configure error %q does not name %s and %s", err, tt.option, tt.wantErr)
			}
		})
	}
}

// Upstream TestTlsConfig.test_tls_clienthello, extended with the branches the
// upstream test leaves to coverage.
func TestTLSClientHello(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		serverTLS bool
		strategy  string
		want      bool
	}{
		"success: no server tls":              {want: false},
		"success: server tls and eager":       {serverTLS: true, want: true},
		"success: server tls and lazy":        {serverTLS: true, strategy: "lazy", want: false},
		"success: eager without a server tls": {strategy: "eager", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, m, opts := newTLSConfig(t)
			if tt.strategy != "" {
				if err := m.Do(t.Context(), func(ctx context.Context) error {
					if err := opts.Add(ctx, "connection_strategy", options.TypeStr, "eager", "Determine how server connections should be established.", options.WithChoices("eager", "lazy")); err != nil {
						return err
					}
					return opts.Update(ctx, map[string]any{"connection_strategy": tt.strategy})
				}); err != nil {
					t.Fatal(err)
				}
			}
			connCtx := testContext(opts)
			connCtx.Server.TLS = tt.serverTLS
			d := &hookdata.ClientHello{Context: connCtx}
			if err := tc.TLSClientHello(t.Context(), d); err != nil {
				t.Fatal(err)
			}
			if d.EstablishServerTLSFirst != tt.want {
				t.Errorf("EstablishServerTLSFirst = %t, want %t", d.EstablishServerTLSFirst, tt.want)
			}
		})
	}
}

// serverPEM names the certificate and key files of the test origin server.
type serverPEM struct{ cert, key string }

var (
	trustedLeaf   = serverPEM{"mitmproxy-net/verificationcerts/trusted-leaf.crt", "mitmproxy-net/verificationcerts/trusted-leaf.key"}
	trustedLeafIP = serverPEM{"mitmproxy-net/verificationcerts/trusted-leaf-ip.crt", "mitmproxy-net/verificationcerts/trusted-leaf-ip.key"}
	selfSigned    = serverPEM{"mitmproxy-net/verificationcerts/self-signed.crt", "mitmproxy-net/verificationcerts/self-signed.key"}
)

// doHandshake runs a real TLS handshake over an in-memory pipe: the
// configuration under test dials, a test origin with the given certificate
// accepts. The deadline is only a hang detector.
func doHandshake(t *testing.T, cfg *tls.Config, origin serverPEM, mutate func(*tls.Config)) (clientState, serverState tls.ConnectionState, clientErr error) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(testutil.FixturePath(t, origin.cert), testutil.FixturePath(t, origin.key))
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if mutate != nil {
		mutate(serverCfg)
	}

	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(30 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	server := tls.Server(serverConn, serverCfg)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()

	client := tls.Client(clientConn, cfg)
	clientErr = client.Handshake()
	serverErr := <-serverDone
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	if clientErr == nil {
		clientState = client.ConnectionState()
	}
	if serverErr == nil {
		serverState = server.ConnectionState()
	}
	return clientState, serverState, clientErr
}

// Upstream TestTlsConfig.test_tls_start_server_cannot_verify,
// test_tls_start_server_verify_failed, test_tls_start_server_verify_ok,
// test_tls_start_server_insecure, test_client_cert_file and the server half
// of test_alpn_selection.
func TestTLSStartServer(t *testing.T) {
	t.Parallel()
	trustedRoot := "mitmproxy-net/verificationcerts/trusted-root.crt"
	tests := map[string]struct {
		opts    map[string]any
		setup   func(t *testing.T, c *hookdata.Context)
		wantErr string
		origin  *serverPEM
		mutate  func(*tls.Config)
		wantBad bool
		check   func(t *testing.T, c *hookdata.Context, d *hookdata.TLS, clientState, serverState tls.ConnectionState)
	}{
		"error: empty sni opts out of verification": {
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
				c.Server.SNI = new("")
			},
			wantErr: "Cannot validate certificate hostname without SNI",
		},
		"error: no server address": {
			wantErr: "server address",
		},
		"error: handshake with an untrusted server fails": {
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Client.ALPNOffers = bss("h2")
				c.Client.CipherList = []string{"TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-SHA"}
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin:  &selfSigned,
			wantBad: true,
		},
		"success: verified handshake by dns name": {
			opts: map[string]any{"ssl_verify_upstream_trusted_ca": trustedRoot},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin: &trustedLeaf,
		},
		"success: verified handshake by ip address": {
			opts: map[string]any{"ssl_verify_upstream_trusted_ca": trustedRoot},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Server.Address = &connection.Address{Host: "192.0.2.42", Port: 443}
			},
			origin: &trustedLeafIP,
			check: func(t *testing.T, c *hookdata.Context, d *hookdata.TLS, clientState, serverState tls.ConnectionState) {
				if got, want := d.Config.ServerName, "192.0.2.42"; got != want {
					t.Errorf("ServerName = %q, want %q", got, want)
				}
			},
		},
		"success: insecure skips verification": {
			opts: map[string]any{"ssl_insecure": true, "http2": false},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin: &selfSigned,
		},
		"success: client certificate from a file": {
			opts: map[string]any{
				"ssl_verify_upstream_trusted_ca": trustedRoot,
				"client_certs":                   "mitmproxy-net/verificationcerts/trusted-client-cert.pem",
			},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin: &trustedLeaf,
			mutate: func(cfg *tls.Config) { cfg.ClientAuth = tls.RequireAnyClientCert },
			check: func(t *testing.T, c *hookdata.Context, d *hookdata.TLS, clientState, serverState tls.ConnectionState) {
				if len(serverState.PeerCertificates) == 0 {
					t.Error("origin received no client certificate")
				}
			},
		},
		"success: client certificate from a directory": {
			opts: map[string]any{
				"ssl_verify_upstream_trusted_ca": trustedRoot,
				"client_certs":                   "mitmproxy-net/verificationcerts",
			},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin: &trustedLeaf,
			mutate: func(cfg *tls.Config) { cfg.ClientAuth = tls.RequireAnyClientCert },
			check: func(t *testing.T, c *hookdata.Context, d *hookdata.TLS, clientState, serverState tls.ConnectionState) {
				if len(serverState.PeerCertificates) == 0 {
					t.Error("origin received no client certificate for its server name")
				}
			},
		},
		"success: alpn offers mirror the client": {
			opts: map[string]any{"ssl_insecure": true},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Client.ALPNOffers = bss("h2", "http/1.1", "foo")
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin: &selfSigned,
			check: func(t *testing.T, c *hookdata.Context, d *hookdata.TLS, clientState, serverState tls.ConnectionState) {
				if diff := gocmp.Diff(bss("http/1.1", "foo"), c.Server.ALPNOffers); diff != "" {
					t.Errorf("server ALPN offers mismatch (-want +got):\n%s", diff)
				}
				if diff := gocmp.Diff([]string{"http/1.1", "foo"}, d.Config.NextProtos); diff != "" {
					t.Errorf("NextProtos mismatch (-want +got):\n%s", diff)
				}
			},
		},
		"success: sni from the client hello": {
			opts: map[string]any{"ssl_insecure": true},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Client.SNI = new("🌈.sni.example")
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin: &selfSigned,
			check: func(t *testing.T, c *hookdata.Context, d *hookdata.TLS, clientState, serverState tls.ConnectionState) {
				if c.Server.SNI == nil || *c.Server.SNI != "🌈.sni.example" {
					t.Errorf("server SNI = %v, want the client's", c.Server.SNI)
				}
				if got, want := d.Config.ServerName, "xn--og8h.sni.example"; got != want {
					t.Errorf("ServerName = %q, want %q", got, want)
				}
			},
		},
		"success: restricted ciphers negotiate the openssl name": {
			opts: map[string]any{
				"ssl_insecure":           true,
				"ciphers_server":         "ECDHE-RSA-AES128-GCM-SHA256",
				"tls_version_server_max": "TLS1_2",
			},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin: &selfSigned,
			check: func(t *testing.T, c *hookdata.Context, d *hookdata.TLS, clientState, serverState tls.ConnectionState) {
				if got, want := clientState.CipherSuite, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; got != uint16(want) {
					t.Fatalf("negotiated suite = %#x, want %#x", got, want)
				}
				name, ok := tlsnames.OpenSSL(clientState.CipherSuite)
				if !ok || name != "ECDHE-RSA-AES128-GCM-SHA256" {
					t.Errorf("OpenSSL name = %q, %t, want ECDHE-RSA-AES128-GCM-SHA256", name, ok)
				}
			},
		},
		"success: curve preference applies": {
			opts: map[string]any{"ssl_insecure": true, "tls_ecdh_curve_server": "secp384r1"},
			setup: func(t *testing.T, c *hookdata.Context) {
				c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
			},
			origin: &selfSigned,
			check: func(t *testing.T, c *hookdata.Context, d *hookdata.TLS, clientState, serverState tls.ConnectionState) {
				if diff := gocmp.Diff([]tls.CurveID{tls.CurveP384}, d.Config.CurvePreferences); diff != "" {
					t.Errorf("CurvePreferences mismatch (-want +got):\n%s", diff)
				}
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, m, opts := newTLSConfig(t)
			if tt.opts != nil {
				values := make(map[string]any, len(tt.opts))
				for k, v := range tt.opts {
					if s, ok := v.(string); ok && strings.HasPrefix(s, "mitmproxy-net/") {
						v = testutil.FixturePath(t, s)
					}
					if s, ok := v.(string); ok && (strings.HasPrefix(k, "ciphers_") || strings.HasPrefix(k, "ssl_verify") || k == "client_certs") {
						v = &s
					}
					values[k] = v
				}
				if err := configure(t, m, opts, values); err != nil {
					t.Fatal(err)
				}
			}
			connCtx := testContext(opts)
			if tt.setup != nil {
				tt.setup(t, connCtx)
			}
			d := &hookdata.TLS{Conn: &connCtx.Server.Connection, Context: connCtx}
			err := tc.TLSStartServer(t.Context(), d)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("TLSStartServer error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if d.Config == nil {
				t.Fatal("TLSStartServer left Config nil")
			}

			// A configuration provided by a user addon is not replaced.
			existing := d.Config
			if err := tc.TLSStartServer(t.Context(), d); err != nil {
				t.Fatal(err)
			}
			if d.Config != existing {
				t.Fatal("TLSStartServer replaced an existing configuration")
			}

			if tt.origin == nil {
				if tt.check != nil {
					tt.check(t, connCtx, d, tls.ConnectionState{}, tls.ConnectionState{})
				}
				return
			}
			clientState, serverState, clientErr := doHandshake(t, d.Config, *tt.origin, tt.mutate)
			if tt.wantBad {
				if clientErr == nil {
					t.Fatal("handshake with an untrusted origin succeeded")
				}
				return
			}
			if clientErr != nil {
				t.Fatalf("handshake: %v", clientErr)
			}
			if tt.check != nil {
				tt.check(t, connCtx, d, clientState, serverState)
			}
		})
	}
}

// TestKeyLogDone checks shutdown closure without reopening the key log.
func TestKeyLogDone(t *testing.T) {
	tests := map[string]struct {
		enabled    bool
		closeEarly bool
	}{
		"success: disabled":         {},
		"success: opened log":       {enabled: true},
		"error: already closed log": {enabled: true, closeEarly: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := ""
			if tt.enabled {
				path = t.TempDir() + "/sslkeylog.txt"
			}
			t.Setenv("SSLKEYLOGFILE", path)
			tc, m, _ := newTLSConfig(t)
			writer := tc.keyLog()
			var file *os.File
			if tt.enabled {
				var ok bool
				file, ok = writer.(*os.File)
				if !ok {
					t.Fatalf("keyLog() = %T, want *os.File", writer)
				}
				t.Cleanup(func() { _ = file.Close() })
				if tt.closeEarly {
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
				}
			} else if writer != nil {
				t.Fatalf("disabled keyLog() = %T, want nil", writer)
			}
			err := m.Clear(t.Context())
			if diff := gocmp.Diff(tt.closeEarly, errors.Is(err, os.ErrClosed)); diff != "" {
				t.Fatalf("Done error = %v (-want +got):\n%s", err, diff)
			}
			if !tt.closeEarly && err != nil {
				t.Fatal(err)
			}
			if file != nil {
				if _, err := file.Write(nil); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("write after Done = %v, want closed file", err)
				}
			}
			if err := m.Clear(t.Context()); err != nil {
				t.Fatalf("repeated Done = %v", err)
			}
			if tc.keyLog() != nil {
				t.Fatal("key log reopened after Done")
			}
		})
	}
}

// TestKeyLogWriter checks that SSLKEYLOGFILE enables master-secret logging.
func TestKeyLogWriter(t *testing.T) {
	path := t.TempDir() + "/sslkeylog.txt"
	t.Setenv("SSLKEYLOGFILE", path)
	tc, m, opts := newTLSConfig(t)
	insecure := true
	if err := configure(t, m, opts, map[string]any{"ssl_insecure": insecure}); err != nil {
		t.Fatal(err)
	}
	connCtx := testContext(opts)
	connCtx.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
	d := &hookdata.TLS{Conn: &connCtx.Server.Connection, Context: connCtx}
	if err := tc.TLSStartServer(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	if d.Config.KeyLogWriter == nil {
		t.Fatal("KeyLogWriter is nil with SSLKEYLOGFILE set")
	}
	if _, _, clientErr := doHandshake(t, d.Config, selfSigned, nil); clientErr != nil {
		t.Fatal(clientErr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CLIENT_HANDSHAKE_TRAFFIC_SECRET") && !strings.Contains(string(data), "CLIENT_RANDOM") {
		t.Errorf("key log file holds no secrets: %q", data)
	}
}
