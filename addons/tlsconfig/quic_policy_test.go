// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"context"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

func TestQUICUpstreamChain(t *testing.T) {
	// py:mitmproxy/addons/tlsconfig.py:395-417 appends upstream certificates
	// after the configured entry chain without removing its first certificate.
	tests := map[string]struct {
		appendChain bool
	}{
		"success: entry chain only":         {},
		"success: entry and upstream chain": {appendChain: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc, manager, opts := newTLSConfig(t)
			if err := configure(t, manager, opts, map[string]any{
				"upstream_cert":                      false,
				"add_upstream_certs_to_client_chain": tt.appendChain,
			}); err != nil {
				t.Fatal(err)
			}
			pem := testutil.Fixture(t, "mitmproxy-net/verificationcerts/trusted-leaf.crt")
			upstream, err := certs.ParseCert(pem)
			if err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			c.Client.SNI = new("client.test")
			c.Server.CertificateList = [][]byte{pem}
			d := &hookdata.QUICTLS{Conn: &c.Client.Connection, Context: c}
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				if err := tc.QUICStartClient(ctx, d); err != nil {
					return err
				}
				if d.Settings == nil {
					t.Fatal("missing client settings")
				}
				var want [][]byte
				for _, cert := range tc.store.DefaultChainCerts() {
					want = append(want, cert.X509().Raw)
				}
				if tt.appendChain {
					want = append(want, upstream.X509().Raw)
				}
				var got [][]byte
				for _, cert := range d.Settings.CertificateChain {
					got = append(got, cert.Raw)
				}
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Errorf("chain (-want +got):\n%s", diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQUICSettingsErrors(t *testing.T) {
	tests := map[string]struct {
		client bool
		setup  func(*hookdata.Context)
		want   string
	}{
		"error: non-ASCII client ALPN":    {client: true, setup: func(c *hookdata.Context) { c.Client.ALPNOffers = [][]byte{{0xff}} }, want: "not ASCII"},
		"error: non-ASCII origin ALPN":    {setup: func(c *hookdata.Context) { c.Server.ALPNOffers = [][]byte{{0xff}} }, want: "not ASCII"},
		"error: unknown client cipher":    {client: true, setup: func(c *hookdata.Context) { c.Client.CipherList = []string{"unknown"} }, want: "ciphers_client"},
		"error: unknown origin cipher":    {setup: func(c *hookdata.Context) { c.Server.CipherList = []string{"unknown"} }, want: "ciphers_server"},
		"error: origin without address":   {setup: func(c *hookdata.Context) { c.Server.Address = nil }, want: "server address"},
		"error: malformed upstream chain": {client: true, setup: func(c *hookdata.Context) { c.Server.CertificateList = [][]byte{[]byte("not a certificate")} }, want: "upstream certificate"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc, manager, opts := newTLSConfig(t)
			if err := configure(t, manager, opts, map[string]any{"upstream_cert": false, "add_upstream_certs_to_client_chain": true}); err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			c.Server.Address = &connection.Address{Host: "origin.test", Port: 443}
			if tt.setup != nil {
				tt.setup(c)
			}
			d := &hookdata.QUICTLS{Context: c, Conn: &c.Server.Connection}
			if tt.client {
				d.Conn = &c.Client.Connection
			}
			err := manager.Do(t.Context(), func(ctx context.Context) error {
				if tt.client {
					return tc.QUICStartClient(ctx, d)
				}
				return tc.QUICStartServer(ctx, d)
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if d.Settings != nil {
				t.Error("failed handler published partial settings")
			}
		})
	}
}
