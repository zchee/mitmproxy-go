// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"context"
	"crypto"
	"crypto/tls"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

func TestQUICStartClient(t *testing.T) {
	// py:test/mitmproxy/addons/test_tlsconfig.py:test_quic_start_client.
	// These configuration rows precede real QUIC handshakes in the layer tests.
	tests := map[string]struct {
		clientALPN []byte
		serverALPN []byte
		offers     [][]byte
		want       []string
	}{
		"success: client offers":                    {offers: bss("h3", "custom"), want: []string{"h3", "custom"}},
		"success: client selected protocol":         {clientALPN: []byte("custom"), offers: bss("h3"), want: []string{"custom"}},
		"success: upstream selected protocol":       {serverALPN: []byte("h3"), offers: bss("custom"), want: []string{"h3"}},
		"success: both selected protocols retained": {clientALPN: []byte("client"), serverALPN: []byte("server"), want: []string{"client", "server"}},
		"success: duplicate selections retained":    {clientALPN: []byte("h3"), serverALPN: []byte("h3"), want: []string{"h3", "h3"}},
		"success: no protocols":                     {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc, manager, opts := newTLSConfig(t)
			if err := configure(t, manager, opts, map[string]any{"ciphers_client": new("TLS_CHACHA20_POLY1305_SHA256")}); err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			c.Client.SNI = new("example.mitmproxy.org")
			c.Client.ALPN, c.Server.ALPN, c.Client.ALPNOffers = tt.clientALPN, tt.serverALPN, tt.offers
			d := &hookdata.QUICTLS{Conn: &c.Client.Connection, Context: c}
			if err := manager.Hook(t.Context(), addon.QUICStartClientHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(context.Context) error {
				if d.Settings == nil || d.Settings.Certificate == nil || d.Settings.CertificatePrivateKey == nil {
					t.Fatal("client hook did not supply leaf and private key")
				}
				if diff := gocmp.Diff(tt.want, d.Settings.ALPNProtocols); diff != "" {
					t.Errorf("ALPN (-want +got):\n%s", diff)
				}
				if diff := gocmp.Diff([]string{"example.mitmproxy.org"}, d.Settings.Certificate.DNSNames); diff != "" {
					t.Errorf("leaf SAN (-want +got):\n%s", diff)
				}
				signer, ok := d.Settings.CertificatePrivateKey.(crypto.Signer)
				if !ok {
					t.Fatal("certificate key is not a signer")
				}
				public, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
				if !ok || !public.Equal(d.Settings.Certificate.PublicKey) {
					t.Error("certificate and private key do not match")
				}
				if diff := gocmp.Diff([]uint16{tls.TLS_CHACHA20_POLY1305_SHA256}, d.Settings.CipherSuites); diff != "" {
					t.Errorf("cipher settings (-want +got):\n%s", diff)
				}
				chain := tc.store.DefaultChainCerts()
				if len(d.Settings.CertificateChain) != len(chain) {
					t.Fatalf("chain length = %d, want %d", len(d.Settings.CertificateChain), len(chain))
				}
				for i, cert := range chain {
					if diff := gocmp.Diff(cert.X509().Raw, d.Settings.CertificateChain[i].Raw); diff != "" {
						t.Errorf("chain certificate %d (-want +got):\n%s", i, diff)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQUICStartServer(t *testing.T) {
	// py:test/mitmproxy/addons/test_tlsconfig.py:
	// test_quic_start_server_verify_ok and test_quic_start_server_insecure.
	tests := map[string]struct {
		host     string
		sni      *string
		offers   [][]byte
		insecure bool
		wantALPN []string
	}{
		"success: DNS verification settings":   {host: "example.mitmproxy.org", wantALPN: []string{"h3"}},
		"success: IP verification settings":    {host: "192.0.2.42", wantALPN: []string{"h3"}},
		"success: insecure with client offers": {host: "example.mitmproxy.org", offers: bss("h3"), insecure: true, wantALPN: []string{"h3"}},
		"success: client SNI and offers":       {host: "origin.test", sni: new("client.test"), offers: bss("custom", "h3"), wantALPN: []string{"custom", "h3"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, manager, opts := newTLSConfig(t)
			caFile := testutil.FixturePath(t, "mitmproxy-net/verificationcerts/trusted-root.crt")
			caPath := t.TempDir()
			if err := configure(t, manager, opts, map[string]any{
				"ssl_insecure":                        tt.insecure,
				"ssl_verify_upstream_trusted_ca":      &caFile,
				"ssl_verify_upstream_trusted_confdir": &caPath,
				"ciphers_server":                      new("TLS_AES_128_GCM_SHA256"),
			}); err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			c.Server.Address = &connection.Address{Host: tt.host, Port: 443}
			c.Client.SNI, c.Client.ALPNOffers = tt.sni, tt.offers
			d := &hookdata.QUICTLS{Conn: &c.Server.Connection, Context: c}
			if err := manager.Hook(t.Context(), addon.QUICStartServerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(context.Context) error {
				if d.Settings == nil || d.Settings.VerifyMode == nil {
					t.Fatal("server hook left settings or verification mode nil")
				}
				wantMode := hookdata.VerifyRequired
				if tt.insecure {
					wantMode = hookdata.VerifyNone
				}
				if *d.Settings.VerifyMode != wantMode || d.Settings.CAFile == nil || *d.Settings.CAFile != caFile || d.Settings.CAPath == nil || *d.Settings.CAPath != caPath {
					t.Errorf("verification/trust settings = %+v", d.Settings)
				}
				if diff := gocmp.Diff(tt.wantALPN, d.Settings.ALPNProtocols); diff != "" {
					t.Errorf("ALPN (-want +got):\n%s", diff)
				}
				wantSNI := tt.host
				if tt.sni != nil {
					wantSNI = *tt.sni
				}
				if c.Server.SNI == nil || *c.Server.SNI != wantSNI {
					t.Errorf("server SNI = %v, want %q", c.Server.SNI, wantSNI)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
