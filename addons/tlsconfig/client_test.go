// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// The tests of the client-facing half of the addon: certificate selection,
// tls_start_client and the CRL request hook. The comment table mapping them
// to upstream's test functions is at the top of tlsconfig_test.go.

package tlsconfig

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// Upstream TestTlsConfig.test_get_cert.
func TestGetCert(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fixture          string
		sni              string
		server           string
		noUpstream       bool
		noSockname       bool
		wantNames        []certs.GeneralName
		wantOrganization string
	}{
		"success: unknown server uses local IP": {
			wantNames: []certs.GeneralName{certs.IPAddress(netip.MustParseAddr("127.0.0.1"))},
		},
		"success: upstream subject and server address": {
			fixture: "mitmproxy-net/verificationcerts/trusted-leaf.crt", server: "server-address.example",
			wantNames:        []certs.GeneralName{certs.DNSName("example.mitmproxy.org"), certs.IPAddress(netip.MustParseAddr("127.0.0.1")), certs.DNSName("server-address.example")},
			wantOrganization: "mitmproxy",
		},
		"success: unicode SNI replaces local IP": {
			fixture: "mitmproxy-net/verificationcerts/trusted-leaf.crt", sni: "🌈.sni.example", server: "server-address.example",
			wantNames:        []certs.GeneralName{certs.DNSName("example.mitmproxy.org"), certs.DNSName("xn--og8h.sni.example"), certs.DNSName("server-address.example")},
			wantOrganization: "mitmproxy",
		},
		"success: duplicate names retain first occurrence": {
			fixture: "mitmproxy-net/verificationcerts/trusted-leaf.crt", sni: "example.mitmproxy.org", server: "example.mitmproxy.org",
			wantNames: []certs.GeneralName{certs.DNSName("example.mitmproxy.org")}, wantOrganization: "mitmproxy",
		},
		"success: disabled upstream certificate option": {
			fixture: "mitmproxy-net/verificationcerts/trusted-leaf.crt", sni: "client.example", server: "server.example", noUpstream: true,
			wantNames: []certs.GeneralName{certs.DNSName("client.example"), certs.DNSName("server.example")},
		},
		"success: invalid upstream country does not prevent issuance": {
			fixture:   "mitmproxy/invalid-subject.pem",
			wantNames: []certs.GeneralName{certs.DNSName("siavash"), certs.IPAddress(netip.MustParseAddr("127.0.0.1"))}, wantOrganization: "siavash",
		},
		"success: SNI does not need a socket address": {
			sni: "client.example", noSockname: true,
			wantNames: []certs.GeneralName{certs.DNSName("client.example")},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, m, opts := newTLSConfig(t)
			if err := configure(t, m, opts, map[string]any{"upstream_cert": !tt.noUpstream}); err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			if tt.fixture != "" {
				c.Server.CertificateList = [][]byte{testutil.Fixture(t, tt.fixture)}
			}
			if tt.sni != "" {
				c.Client.SNI = new(tt.sni)
			}
			if tt.server != "" {
				c.Server.Address = &connection.Address{Host: tt.server, Port: 443}
			}
			if tt.noSockname {
				c.Client.Sockname = nil
			}
			entry, err := tc.getCert(c)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.wantNames, entry.Cert.AltNames(), gocmp.Comparer(func(a, b certs.GeneralName) bool { return a == b })); diff != "" {
				t.Errorf("SANs (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantNames[0].String(), entry.Cert.CN()); diff != "" {
				t.Errorf("common name (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantOrganization, entry.Cert.Organization()); diff != "" {
				t.Errorf("organization (-want +got):\n%s", diff)
			}
		})
	}
}

// Upstream TestTlsConfig.test_crl_substitution.
func TestCRLSubstitution(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		cert      string
		expectCRL bool
	}{
		"success: crl distribution point rewritten to the ca serial": {cert: "mitmproxy-net/verificationcerts/trusted-leaf.crt", expectCRL: true},
		"success: certificate without crl distribution point":        {cert: "mitmproxy-net/verificationcerts/trusted-root.crt"},
		"success: unparsable crl url is dropped":                     {cert: "mitmproxy-net/verificationcerts/invalid-crl.crt"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, _, opts := newTLSConfig(t)
			connCtx := testContext(opts)
			connCtx.Server.CertificateList = [][]byte{testutil.Fixture(t, tt.cert)}
			entry, err := tc.getCert(connCtx)
			if err != nil {
				t.Fatal(err)
			}
			points := entry.Cert.CRLDistributionPoints()
			if !tt.expectCRL {
				if len(points) != 0 {
					t.Fatalf("CRL distribution points = %v, want none", points)
				}
				return
			}
			if len(points) == 0 || !strings.HasSuffix(points[0], tc.crlPath()) {
				t.Fatalf("CRL distribution points = %v, want the first to end in %q", points, tc.crlPath())
			}
		})
	}
}

// Upstream TestTlsConfig.test_crl_request.
func TestCRLRequest(t *testing.T) {
	t.Parallel()
	tc, m, _ := newTLSConfig(t)
	tests := map[string]struct {
		path         string
		notLive      bool
		flags        []testflow.With
		wantResponse bool
	}{
		"success: unrelated request untouched":      {path: "/other.crl"},
		"success: CRL path":                         {path: tc.crlPath(), wantResponse: true},
		"success: path suffix":                      {path: "/nested" + tc.crlPath(), wantResponse: true},
		"success: query after token does not match": {path: tc.crlPath() + "?query"},
		"success: dead flow untouched":              {path: tc.crlPath(), notLive: true},
		"success: errored flow untouched":           {path: tc.crlPath(), flags: []testflow.With{testflow.WithError}},
		"success: existing response untouched":      {path: tc.crlPath(), flags: []testflow.With{testflow.WithResponse}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TFlow(tt.flags...)
			f.Request.Path = tt.path
			f.Live = !tt.notLive
			before := f.Response
			if err := m.Do(t.Context(), func(ctx context.Context) error { return tc.Request(ctx, f) }); err != nil {
				t.Fatal(err)
			}
			if !tt.wantResponse {
				if f.Response != before {
					t.Fatal("request hook changed a response it should not handle")
				}
				return
			}
			if f.Response == nil {
				t.Fatal("a request for the CRL path got no response")
			}
			if diff := gocmp.Diff(200, f.Response.StatusCode); diff != "" {
				t.Errorf("status (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff("application/pkix-crl", f.Response.Headers.Get("Content-Type")); diff != "" {
				t.Errorf("Content-Type (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tc.store.DefaultCRL(), f.Response.RawContent); diff != "" {
				t.Errorf("CRL body (-want +got):\n%s", diff)
			}
			crl, err := x509.ParseRevocationList(f.Response.RawContent)
			if err != nil {
				t.Fatalf("parse served CRL: %v", err)
			}
			if err := crl.CheckSignatureFrom(tc.store.DefaultCA().X509()); err != nil {
				t.Fatalf("served CRL signature: %v", err)
			}
		})
	}
}

// handshakeAsServer runs a real TLS handshake over an in-memory pipe: the
// configuration under test accepts, a test client dials. The deadline is
// only a hang detector. It returns the client's view of the connection.
func handshakeAsServer(t *testing.T, cfg, clientCfg *tls.Config) tls.ConnectionState {
	t.Helper()
	if clientCfg == nil {
		clientCfg = &tls.Config{}
	}
	// The test client inspects the presented certificate instead of
	// verifying it against a root.
	clientCfg.InsecureSkipVerify = true

	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(30 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	server := tls.Server(serverConn, cfg)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()

	client := tls.Client(clientConn, clientCfg)
	clientErr := client.Handshake()
	serverErr := <-serverDone
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	return client.ConnectionState()
}

// Upstream TestTlsConfig.test_tls_start_client.
func TestTLSStartClient(t *testing.T) {
	t.Parallel()
	tc, m, opts := newTLSConfig(t)
	if err := configure(t, m, opts, map[string]any{
		"certs":          []string{testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-leaf.pem")},
		"ciphers_client": "ECDHE-ECDSA-AES128-GCM-SHA256",
	}); err != nil {
		t.Fatal(err)
	}
	connCtx := testContext(opts)
	d := &hookdata.TLS{Conn: &connCtx.Client.Connection, Context: connCtx}
	if err := tc.TLSStartClient(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	if d.Config == nil {
		t.Fatal("no configuration was built")
	}

	// A configuration provided by a user addon is not overwritten.
	first := d.Config
	if err := tc.TLSStartClient(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	if d.Config != first {
		t.Fatal("an existing configuration was replaced")
	}

	// The cipher option is recorded on the connection and restricts the
	// configuration.
	if want := []string{"ECDHE-ECDSA-AES128-GCM-SHA256"}; !slices.Equal(connCtx.Client.CipherList, want) {
		t.Errorf("client cipher list = %v, want %v", connCtx.Client.CipherList, want)
	}
	if want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}; !slices.Equal(d.Config.CipherSuites, want) {
		t.Errorf("cipher suites = %v, want %v", d.Config.CipherSuites, want)
	}

	// The chosen leaf is published as the client connection's MitmCert.
	mitmCert, err := certs.ParseCert(connCtx.Client.MitmCert)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := mitmCert.CN(), "example.mitmproxy.org"; got != want {
		t.Errorf("MitmCert CN = %q, want %q", got, want)
	}

	// A real handshake presents the configured certificate.
	state := handshakeAsServer(t, d.Config, nil)
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	if got, want := state.PeerCertificates[0].DNSNames, []string{"example.mitmproxy.org"}; !slices.Equal(got, want) {
		t.Fatalf("presented SANs = %v, want %v", got, want)
	}
}

// The ciphers_client acceptance row: a two-suite list restricts the client
// side of the proxy to exactly those suites, and a TLS 1.2 handshake
// negotiates one of them.
func TestCiphersClientRestriction(t *testing.T) {
	t.Parallel()
	tc, m, opts := newTLSConfig(t)
	if err := configure(t, m, opts, map[string]any{"ciphers_client": "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"}); err != nil {
		t.Fatal(err)
	}
	connCtx := testContext(opts)
	d := &hookdata.TLS{Conn: &connCtx.Client.Connection, Context: connCtx}
	if err := tc.TLSStartClient(t.Context(), d); err != nil {
		t.Fatal(err)
	}

	want := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
	if !slices.Equal(d.Config.CipherSuites, want) {
		t.Fatalf("cipher suites = %v, want %v", d.Config.CipherSuites, want)
	}

	// TLS 1.3 ignores the suite restriction by design, so the handshake
	// check pins the client to TLS 1.2.
	state := handshakeAsServer(t, d.Config, &tls.Config{MaxVersion: tls.VersionTLS12}) //nolint:gosec // The restriction under test applies to TLS 1.2.
	if !slices.Contains(want, state.CipherSuite) {
		t.Fatalf("negotiated suite %#04x, want one of %v", state.CipherSuite, want)
	}
}

// layerStub pretends to be a protocol layer of the given kind in the
// connection context's stack.
type layerStub hookdata.LayerKind

func (l layerStub) Kind() hookdata.LayerKind { return hookdata.LayerKind(l) }

// Upstream TestTlsConfig.test_no_h2_proxy: in secure web proxy mode the
// client-facing protocol is forced to HTTP/1, overriding a preset protocol.
func TestNoH2Proxy(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		layers []any
		want   []string
	}{
		"success: secure web proxy forces http/1.1": {
			layers: []any{layerStub(hookdata.LayerRegular), layerStub(hookdata.LayerClientTLS)},
			want:   []string{"http/1.1"},
		},
		"success: HTTP child preserves the secure proxy exception": {
			layers: []any{layerStub(hookdata.LayerRegular), layerStub(hookdata.LayerClientTLS), layerStub(hookdata.LayerHTTP)},
			want:   []string{"http/1.1"},
		},
		"success: plain proxy tunnel negotiates h2": {
			layers: []any{layerStub(hookdata.LayerRegular), layerStub(hookdata.LayerHTTP), layerStub(hookdata.LayerServerTLS), layerStub(hookdata.LayerClientTLS), layerStub(hookdata.LayerHTTP)},
			want:   []string{"h2"},
		},
		"success: secure proxy inner tunnel negotiates h2": {
			layers: []any{layerStub(hookdata.LayerRegular), layerStub(hookdata.LayerClientTLS), layerStub(hookdata.LayerHTTP), layerStub(hookdata.LayerServerTLS), layerStub(hookdata.LayerClientTLS), layerStub(hookdata.LayerHTTP)},
			want:   []string{"h2"},
		},
		"success: reverse proxy negotiates h2": {
			layers: []any{layerStub(hookdata.LayerReverse), layerStub(hookdata.LayerClientTLS), layerStub(hookdata.LayerHTTP)},
			want:   []string{"h2"},
		},
		"success: other stacks keep the preset protocol": {
			want: []string{"h2"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, _, opts := newTLSConfig(t)
			connCtx := testContext(opts)
			connCtx.Layers = tt.layers
			connCtx.Client.ALPN = []byte("h2")
			connCtx.Client.ALPNOffers = [][]byte{[]byte("h2"), []byte("http/1.1")}
			d := &hookdata.TLS{Conn: &connCtx.Client.Connection, Context: connCtx}
			if err := tc.TLSStartClient(t.Context(), d); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(d.Config.NextProtos, tt.want) {
				t.Fatalf("NextProtos = %v, want %v", d.Config.NextProtos, tt.want)
			}
		})
	}
}

// writeExpiredCA writes a CA file in mitmproxy's layout (PKCS#1 private key
// followed by the certificate) whose certificate expired yesterday.
func writeExpiredCA(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mitmproxy", Organization: []string{"mitmproxy"}},
		NotBefore:             time.Now().Add(-2 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Upstream TestTlsConfig.test_ca_expired, with a real expired CA on disk
// instead of a monkeypatched has_expired.
func TestCAExpired(t *testing.T) {
	logs := captureLogs(t)
	confdir := t.TempDir()
	writeExpiredCA(t, filepath.Join(confdir, options.ConfBasename+"-ca.pem"))

	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": confdir}); err != nil {
		t.Fatal(err)
	}
	tc := New(opts)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), tc); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), tc.Running); err != nil {
		t.Fatal(err)
	}
	if want := "The mitmproxy certificate authority has expired"; !strings.Contains(logs.text(t), want) {
		t.Fatalf("running logged %q, want it to contain %q", logs.text(t), want)
	}
}

func TestTLSStartClientChain(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		chainFile string
		addOrigin bool
		wantPeers int
	}{
		"success: generated leaf excludes its signing root":         {wantPeers: 1},
		"success: configured chain keeps intermediate certificates": {chainFile: "trusted-chain.pem", wantPeers: 2},
		"success: upstream certificates follow the selected leaf":   {addOrigin: true, wantPeers: 3},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, m, opts := newTLSConfig(t)
			values := map[string]any{"add_upstream_certs_to_client_chain": tt.addOrigin, "request_client_cert": true}
			if tt.chainFile != "" {
				values["certs"] = []string{testutil.FixturePath(t, "mitmproxy-net/verificationcerts/"+tt.chainFile)}
			}
			if err := configure(t, m, opts, values); err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			c.Server.CertificateList = [][]byte{
				testutil.Fixture(t, "mitmproxy-net/verificationcerts/trusted-leaf.crt"),
				testutil.Fixture(t, "mitmproxy-net/verificationcerts/trusted-root.crt"),
			}
			d := &hookdata.TLS{Conn: &c.Client.Connection, Context: c}
			if err := tc.TLSStartClient(t.Context(), d); err != nil {
				t.Fatal(err)
			}
			requested := false
			state := handshakeAsServer(t, d.Config, &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				requested = true
				return &tls.Certificate{}, nil
			}})
			if !requested {
				t.Fatal("request_client_cert did not send CertificateRequest")
			}
			if got := len(state.PeerCertificates); got != tt.wantPeers {
				t.Fatalf("presented %d certificates, want %d", got, tt.wantPeers)
			}
			if tt.addOrigin {
				for i, raw := range c.Server.CertificateList {
					cert, err := certs.ParseCert(raw)
					if err != nil {
						t.Fatal(err)
					}
					if !state.PeerCertificates[i+1].Equal(cert.X509()) {
						t.Errorf("chain certificate %d does not match the origin", i+1)
					}
				}
			}
		})
	}
}

func TestTLSStartClientALPN(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		secure         bool
		disabled       bool
		preset, origin []byte
		offers         [][]byte
		want           string
	}{
		"success: h2 capable client negotiates h2":                           {offers: bss("h2", "http/1.1"), want: "h2"},
		"success: disabled http2 falls back to http1":                        {disabled: true, offers: bss("h2", "http/1.1"), want: "http/1.1"},
		"success: disabled http2 with only h2 selects nothing":               {disabled: true, offers: bss("h2")},
		"success: origin selection is mirrored":                              {origin: []byte("http/1.1"), offers: bss("h2", "http/1.1"), want: "http/1.1"},
		"success: origin refusal is mirrored":                                {origin: []byte{}, offers: bss("h2", "http/1.1")},
		"success: origin h2 is mirrored":                                     {origin: []byte("h2"), offers: bss("http/1.1", "h2"), want: "h2"},
		"success: preset wins over origin":                                   {preset: []byte("http/1.1"), origin: []byte("h2"), offers: bss("h2", "http/1.1"), want: "http/1.1"},
		"success: empty preset selects nothing":                              {preset: []byte{}, offers: bss("h2", "http/1.1")},
		"success: unoffered preset selects nothing":                          {preset: []byte("custom"), offers: bss("h2", "http/1.1")},
		"success: secure proxy negotiates http1":                             {secure: true, offers: bss("h2", "http/1.1"), want: "http/1.1"},
		"success: secure proxy overrides h2 origin":                          {secure: true, origin: []byte("h2"), offers: bss("h2", "http/1.1"), want: "http/1.1"},
		"success: secure proxy permits a handshake without overlapping ALPN": {secure: true, offers: bss("h2")},
		"success: no ALPN offered":                                           {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, m, opts := newTLSConfig(t)
			if tt.disabled {
				if err := configure(t, m, opts, map[string]any{"http2": false}); err != nil {
					t.Fatal(err)
				}
			}
			c := testContext(opts)
			c.Client.ALPNOffers = tt.offers
			c.Client.ALPN, c.Server.ALPN = tt.preset, tt.origin
			if tt.secure {
				c.Layers = []any{layerStub(hookdata.LayerRegular), layerStub(hookdata.LayerClientTLS), layerStub(hookdata.LayerHTTP)}
			}
			d := &hookdata.TLS{Conn: &c.Client.Connection, Context: c}
			if err := tc.TLSStartClient(t.Context(), d); err != nil {
				t.Fatal(err)
			}
			clientCfg := &tls.Config{}
			for _, offer := range tt.offers {
				clientCfg.NextProtos = append(clientCfg.NextProtos, string(offer))
			}
			state := handshakeAsServer(t, d.Config, clientCfg)
			if got := state.NegotiatedProtocol; got != tt.want {
				t.Fatalf("negotiated protocol = %q, want %q", got, tt.want)
			}
			if len(d.Config.NextProtos) > 1 {
				t.Fatalf("NextProtos contains more than one selection: %v", d.Config.NextProtos)
			}
		})
	}
}
