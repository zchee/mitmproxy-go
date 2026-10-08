// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/options"
)

type settingsProvider struct{ settings *hookdata.QUICTLSSettings }

func (p *settingsProvider) QUICStartClient(_ context.Context, d *hookdata.QUICTLS) error {
	d.Settings = p.settings
	return nil
}

func (p *settingsProvider) QUICStartServer(_ context.Context, d *hookdata.QUICTLS) error {
	d.Settings = p.settings
	return nil
}

func TestQUICPolicyOwnedSnapshot(t *testing.T) {
	cert, _ := originCertificate(t)
	leaf, err := x509.ParseCertificate(cert.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ client, opaque bool }{
		"client settings": {client: true}, "server settings": {},
		"client opaque signer": {client: true, opaque: true}, "server opaque signer": {opaque: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			key := cert.Certificates[0].PrivateKey
			if tt.opaque {
				key = &opaqueSigner{Signer: key.(crypto.Signer)}
			}
			certificate := *leaf
			certificate.Raw = bytes.Clone(leaf.Raw)
			chain, err := x509.ParseCertificate(bytes.Clone(cert.Certificates[0].Certificate[1]))
			if err != nil {
				t.Fatal(err)
			}
			caFile, caPath := "original.pem", "original-directory"
			settings := &hookdata.QUICTLSSettings{ALPNProtocols: []string{"raw-test"}, Certificate: &certificate, CertificateChain: []*x509.Certificate{chain}, CertificatePrivateKey: key, CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256}, VerifyMode: new(hookdata.VerifyNone), CAFile: &caFile, CAPath: &caPath}
			opts := options.New()
			manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
			defer manager.Close()
			if err := manager.Add(t.Context(), &settingsProvider{settings: settings}); err != nil {
				t.Fatal(err)
			}
			c := &layer.Context{Data: &hookdata.Context{Client: connection.NewClient(connection.Address{}, connection.Address{}, 1), Server: connection.NewServer(&connection.Address{Host: "origin.test", Port: 443})}, Do: manager.Do, Hooks: &proxy.HookRunner{Manager: manager}}
			policy, err := startPolicy(t.Context(), c, tt.client)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(context.Context) error {
				settings.ALPNProtocols[0] = "changed"
				*settings.VerifyMode = hookdata.VerifyRequired
				*settings.CAFile, *settings.CAPath = "changed.pem", "changed-directory"
				clear(settings.Certificate.Raw)
				clear(settings.CertificateChain[0].Raw)
				settings.CertificatePrivateKey = nil
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if *policy.caFile != "original.pem" || *policy.caPath != "original-directory" {
				t.Fatal("snapshot CA paths changed")
			}
			policy.caFile, policy.caPath = nil, nil
			cfg, err := policy.config(tt.client)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Certificates[0].PrivateKey != key {
				t.Fatal("snapshot lost immutable signing material")
			}
			if diff := gocmp.Diff(cert.Certificates[0].Certificate, cfg.Certificates[0].Certificate); diff != "" {
				t.Fatalf("snapshot certificate DER changed: %s", diff)
			}
			if diff := gocmp.Diff([]string{"raw-test"}, cfg.NextProtos); diff != "" {
				t.Fatal(diff)
			}
			if !tt.client && !cfg.InsecureSkipVerify {
				t.Fatal("snapshot verification policy changed")
			}
			if cfg.MinVersion != tls.VersionTLS13 || len(cfg.CipherSuites) != 0 || cfg.VerifyConnection != nil {
				t.Fatal("TLS 1.3 cipher list added a negotiation rejection")
			}
		})
	}
}

func TestQUICPolicyMissingSettings(t *testing.T) {
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	defer manager.Close()
	c := &layer.Context{Data: &hookdata.Context{Client: connection.NewClient(connection.Address{}, connection.Address{}, 1), Server: connection.NewServer(nil)}, Do: manager.Do, Hooks: &proxy.HookRunner{Manager: manager}}
	if _, err := startPolicy(t.Context(), c, true); err == nil {
		t.Fatal("missing QUIC hook settings accepted")
	}
}
