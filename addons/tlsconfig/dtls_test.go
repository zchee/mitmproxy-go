// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// dtlsPair performs a real DTLS handshake over two fixed-peer loopback sockets.
// Its context timeout only detects hangs; no assertion measures elapsed time.
func dtlsPair(t *testing.T, serverCfg, clientCfg *dtls.Config) (dtls.State, dtls.State) { //nolint:staticcheck // Hook overrides require pion's mutable configuration contract.
	t.Helper()
	serverPacket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverPacket.Close() }()
	clientPacket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientPacket.Close() }()
	server, err := dtls.Server(serverPacket, clientPacket.LocalAddr(), serverCfg) //nolint:staticcheck // Exercise the frozen packet constructor contract.
	if err != nil {
		t.Fatal(err)
	}
	client, err := dtls.Client(clientPacket, serverPacket.LocalAddr(), clientCfg) //nolint:staticcheck // Exercise the frozen packet constructor contract.
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(ctx) }()
	clientErr := client.HandshakeContext(ctx)
	if clientErr != nil {
		cancel()
	}
	serverErr := <-done
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake: client=%v server=%v", clientErr, serverErr)
	}
	serverState, ok := server.ConnectionState()
	if !ok {
		t.Fatal("server state unavailable")
	}
	clientState, ok := client.ConnectionState()
	if !ok {
		t.Fatal("client state unavailable")
	}
	return serverState, clientState
}

func TestDTLSVersionWindows(t *testing.T) {
	tc, m, opts := newTLSConfig(t)
	tests := map[string]struct {
		side string
	}{
		"success: client option windows": {"client"},
		"success: server option windows": {"server"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			accepted, rejected := 0, 0
			for _, minVersion := range tlsVersionNames {
				for _, maxVersion := range tlsVersionNames {
					t.Run(minVersion+"/"+maxVersion, func(t *testing.T) {
						values := map[string]any{
							"tls_version_" + tt.side + "_min": minVersion,
							"tls_version_" + tt.side + "_max": maxVersion,
							"ssl_insecure":                    true,
						}
						if err := configure(t, m, opts, values); err != nil {
							t.Fatal(err)
						}
						c := testContext(opts)
						c.Server.Address = &connection.Address{Host: "example.test", Port: 443}
						d := &hookdata.TLS{Context: c, IsDTLS: true}
						var err error
						if tt.side == "client" {
							d.Conn = &c.Client.Connection
							err = m.Do(t.Context(), func(ctx context.Context) error { return tc.dtlsStartClient(ctx, d) })
						} else {
							d.Conn = &c.Server.Connection
							err = m.Do(t.Context(), func(ctx context.Context) error { return tc.dtlsStartServer(ctx, d) })
						}
						wantAccepted := minVersion != "TLS1_3" && (maxVersion == "UNBOUNDED" || maxVersion == "TLS1_2" || maxVersion == "TLS1_3")
						if !wantAccepted {
							rejected++
							want := fmt.Sprintf("DTLS in mitmproxy-go supports DTLS 1.2 only; tls_version_%s_min=%s and tls_version_%s_max=%s exclude it.", tt.side, minVersion, tt.side, maxVersion)
							if err == nil || err.Error() != want || d.DTLSConfig != nil {
								t.Fatalf("rejected window: error=%v config=%v; want %s", err, d.DTLSConfig, want)
							}
							return
						}
						accepted++
						if err != nil || d.DTLSConfig == nil {
							t.Fatalf("accepted window: error=%v config=%v", err, d.DTLSConfig)
						}
						if tt.side == "client" {
							dtlsPair(t, d.DTLSConfig, &dtls.Config{InsecureSkipVerify: true}) //nolint:staticcheck // Mutable hook contract.
						} else {
							serverData := &hookdata.TLS{Context: c, Conn: &c.Client.Connection, IsDTLS: true}
							if err := configure(t, m, opts, map[string]any{"tls_version_client_min": "TLS1_2", "tls_version_client_max": "UNBOUNDED"}); err != nil {
								t.Fatal(err)
							}
							if err := m.Do(t.Context(), func(ctx context.Context) error { return tc.dtlsStartClient(ctx, serverData) }); err != nil {
								t.Fatal(err)
							}
							dtlsPair(t, serverData.DTLSConfig, d.DTLSConfig)
						}
					})
				}
			}
			if accepted != 15 || rejected != 21 {
				t.Fatalf("windows: %d accepted, %d rejected; want 15/21", accepted, rejected)
			}
		})
	}
}

func TestDTLSCertificateAdapter(t *testing.T) {
	tests := map[string]struct {
		sni  string
		want []certs.GeneralName
	}{
		"success: SNI and origin SANs":                {"example.test", []certs.GeneralName{certs.DNSName("example.test"), certs.DNSName("origin.test")}},
		"success: empty SNI listener and origin SANs": {"", []certs.GeneralName{certs.IPAddress(netip.MustParseAddr("127.0.0.1")), certs.DNSName("origin.test")}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc, m, opts := newTLSConfig(t)
			c := testContext(opts)
			c.Client.SNI = new(tt.sni)
			c.Server.Address = &connection.Address{Host: "origin.test", Port: 443}
			d := &hookdata.TLS{Context: c, Conn: &c.Client.Connection, IsDTLS: true}
			if err := m.Do(t.Context(), func(ctx context.Context) error { return tc.dtlsStartClient(ctx, d) }); err != nil {
				t.Fatal(err)
			}
			cfg := d.DTLSConfig
			if len(cfg.Certificates) != 0 || cfg.GetCertificate == nil {
				t.Fatal("every handshake must reach GetCertificate, including no-SNI clients")
			}
			// A handshake callback must not read addon-owned metadata after dispatch.
			c.Client.SNI = new("changed.test")
			c.Server.Address.Host = "changed-origin.test"
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					certificate, err := cfg.GetCertificate(&dtls.ClientHelloInfo{ServerName: tt.sni})
					if err != nil {
						t.Error(err)
						return
					}
					leaf := certs.NewCert(certificate.Leaf)
					if diff := cmp.Diff(tt.want, leaf.AltNames(), cmp.Comparer(func(a, b certs.GeneralName) bool { return a == b })); diff != "" {
						t.Error(diff)
					}
				})
			}
			wg.Wait()
			_, state := dtlsPair(t, cfg, &dtls.Config{ServerName: tt.sni, InsecureSkipVerify: true}) //nolint:staticcheck // Mutable hook contract.
			leaf, err := x509.ParseCertificate(state.PeerCertificates[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := leaf.CheckSignatureFrom(tc.store.DefaultCA().X509()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDTLSKeyLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dtls.keys")
	t.Setenv("SSLKEYLOGFILE", path)
	tc, m, opts := newTLSConfig(t)
	c := testContext(opts)
	d := &hookdata.TLS{Context: c, Conn: &c.Client.Connection, IsDTLS: true}
	if err := m.Do(t.Context(), func(ctx context.Context) error { return tc.dtlsStartClient(ctx, d) }); err != nil {
		t.Fatal(err)
	}
	if d.DTLSConfig.KeyLogWriter == nil {
		t.Fatal("DTLS key logger not configured")
	}
	dtlsPair(t, d.DTLSConfig, &dtls.Config{InsecureSkipVerify: true}) //nolint:staticcheck // Mutable hook configuration contract.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CLIENT_RANDOM ") {
		t.Fatalf("missing negotiated master secret: %q", data)
	}
}

func TestDTLSMutualAuthentication(t *testing.T) {
	tc, m, opts := newTLSConfig(t)
	if err := configure(t, m, opts, map[string]any{
		"certs":                          []string{testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-leaf.pem")},
		"client_certs":                   testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-leaf.pem"),
		"ssl_verify_upstream_trusted_ca": testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-root.crt"),
		"request_client_cert":            true,
	}); err != nil {
		t.Fatal(err)
	}
	c := testContext(opts)
	c.Client.SNI = new("example.mitmproxy.org")
	c.Server.Address = &connection.Address{Host: "example.mitmproxy.org", Port: 443}
	serverData := &hookdata.TLS{Context: c, Conn: &c.Client.Connection, IsDTLS: true}
	clientData := &hookdata.TLS{Context: c, Conn: &c.Server.Connection, IsDTLS: true}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if err := tc.dtlsStartClient(ctx, serverData); err != nil {
			return err
		}
		return tc.dtlsStartServer(ctx, clientData)
	}); err != nil {
		t.Fatal(err)
	}
	serverState, clientState := dtlsPair(t, serverData.DTLSConfig, clientData.DTLSConfig)
	if len(serverState.PeerCertificates) == 0 || len(clientState.PeerCertificates) == 0 {
		t.Fatal("mutual authentication did not exchange certificates")
	}
}

func TestDTLSConfigOptions(t *testing.T) {
	tests := map[string]struct {
		values map[string]any
		bad    bool
	}{
		"success: defaults": {},
		"success: client certificate request and supported cipher": {values: map[string]any{"request_client_cert": true, "ciphers_client": "ECDHE-RSA-AES128-GCM-SHA256", "ciphers_server": "ECDHE-RSA-AES128-GCM-SHA256"}},
		"error: TLS-only cipher is explicit":                       {values: map[string]any{"ciphers_client": "AES128-SHA", "ciphers_server": "AES128-SHA"}, bad: true},
		"success: trusted CA and client certificate":               {values: map[string]any{"ssl_verify_upstream_trusted_ca": testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-root.crt"), "client_certs": testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-leaf.pem")}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc, m, opts := newTLSConfig(t)
			if err := configure(t, m, opts, tt.values); err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			c.Client.SNI = new("example.test")
			c.Client.ALPNOffers = [][]byte{[]byte("custom-protocol")}
			c.Server.Address = &connection.Address{Host: "origin.test", Port: 443}
			c.Server.ALPN = []byte("custom-protocol")
			for _, side := range []string{"client", "server"} {
				d := &hookdata.TLS{Context: c, IsDTLS: true}
				var err error
				if side == "client" {
					d.Conn = &c.Client.Connection
					err = m.Do(t.Context(), func(ctx context.Context) error { return tc.dtlsStartClient(ctx, d) })
				} else {
					d.Conn = &c.Server.Connection
					err = m.Do(t.Context(), func(ctx context.Context) error { return tc.dtlsStartServer(ctx, d) })
				}
				if tt.bad {
					if err == nil || !strings.Contains(err.Error(), "DTLS") || d.DTLSConfig != nil {
						t.Fatalf("%s unsupported cipher: err=%v config=%v", side, err, d.DTLSConfig)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff([]string{"custom-protocol"}, d.DTLSConfig.SupportedProtocols); diff != "" {
					t.Fatal(diff)
				}
				if _, ok := tt.values["ciphers_"+side]; ok && len(d.DTLSConfig.CipherSuites) != 1 {
					t.Fatalf("%s cipher restriction lost", side)
				}
				if side == "client" && opts.Bool("request_client_cert") && d.DTLSConfig.ClientAuth != dtls.RequestClientCert {
					t.Fatal("client certificate request lost")
				}
				if side == "server" {
					if _, ok := tt.values["client_certs"]; ok && len(d.DTLSConfig.Certificates) != 1 {
						t.Fatal("upstream client certificate lost")
					}
					if _, ok := tt.values["ssl_verify_upstream_trusted_ca"]; ok && d.DTLSConfig.RootCAs == nil {
						t.Fatal("custom trusted roots lost")
					}
				}
				original := d.DTLSConfig
				if side == "client" {
					err = tc.dtlsStartClient(t.Context(), d)
				} else {
					err = tc.dtlsStartServer(t.Context(), d)
				}
				if err != nil || d.DTLSConfig != original || d.Config != nil {
					t.Fatal("user override replaced or wrong-transport configuration installed")
				}
			}
		})
	}
}
