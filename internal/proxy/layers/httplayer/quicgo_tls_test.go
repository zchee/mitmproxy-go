// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
)

type http3OriginSettings struct{ settings *hookdata.QUICTLSSettings }

func (a *http3OriginSettings) QUICStartServer(_ context.Context, data *hookdata.QUICTLS) error {
	data.Settings = a.settings
	return nil
}

func TestHTTP3OriginTLSSettings(t *testing.T) {
	tests := map[string]struct {
		trustFile bool
		trustDir  bool
		insecure  bool
		missing   bool
		unrelated bool
	}{
		"default verification":                 {},
		"explicit trusted CA file":             {trustFile: true},
		"explicit trusted CA directory":        {trustDir: true},
		"CA directory ignores unrelated files": {trustDir: true, unrelated: true},
		"disabled verification":                {insecure: true},
		"missing trusted CA fails":             {trustFile: true, missing: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture, master := newTestStream(t, &streamAddon{})
			key, ca, err := certs.CreateCA("HTTP3 origin settings", "HTTP3 origin root", 2048)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := certs.DummyCert(key, ca, "localhost", []certs.GeneralName{certs.DNSName("localhost")}, "", "")
			if err != nil {
				t.Fatal(err)
			}
			settings := &hookdata.QUICTLSSettings{
				ALPNProtocols:         []string{"h3"},
				Certificate:           leaf.X509(),
				CertificateChain:      []*x509.Certificate{ca.X509()},
				CertificatePrivateKey: key,
			}
			if test.insecure {
				settings.VerifyMode = new(hookdata.VerifyNone)
			}
			if test.trustFile || test.trustDir {
				directory := t.TempDir()
				path := filepath.Join(directory, "root.pem")
				if !test.missing {
					if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.X509().Raw}), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if test.unrelated {
					if err := os.WriteFile(filepath.Join(directory, "README"), []byte("not a certificate"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if test.trustFile {
					settings.CAFile = &path
				} else {
					settings.CAPath = &directory
				}
			}
			if err := master.Do(t.Context(), func(ctx context.Context) error {
				fixture.c.Data.Server = connection.NewServer(&connection.Address{Host: "127.0.0.1", Port: 443})
				fixture.c.Data.Server.SNI = new("localhost")
				return master.Addons.Add(ctx, &http3OriginSettings{settings: settings})
			}); err != nil {
				t.Fatal(err)
			}
			conf, err := http3OriginTLS(t.Context(), fixture.c)
			if test.missing {
				if err == nil {
					t.Fatal("missing CA file did not fail")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if conf.ServerName != "localhost" || conf.InsecureSkipVerify != test.insecure {
				t.Fatalf("origin TLS policy: SNI %q, insecure %v", conf.ServerName, conf.InsecureSkipVerify)
			}
			if test.trustFile || test.trustDir {
				if conf.RootCAs == nil {
					t.Fatal("configured trust roots lost")
				}
				if _, err := leaf.X509().Verify(x509.VerifyOptions{Roots: conf.RootCAs, DNSName: "localhost"}); err != nil {
					t.Fatal("configured roots do not verify origin:", err)
				}
			} else if conf.RootCAs != nil {
				t.Fatal("default system trust roots were replaced")
			}
			if conf.Certificates[0].PrivateKey != key {
				t.Fatal("immutable signer was replaced")
			}
			originalLeaf, originalCA := conf.Certificates[0].Certificate[0][0], conf.Certificates[0].Certificate[1][0]
			if err := master.Do(t.Context(), func(context.Context) error {
				settings.ALPNProtocols[0] = "changed"
				settings.Certificate.Raw[0] ^= 0xff
				settings.CertificateChain[0].Raw[0] ^= 0xff
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"h3"}, conf.NextProtos); diff != "" {
				t.Fatal(diff)
			}
			if conf.Certificates[0].Certificate[0][0] != originalLeaf || conf.Certificates[0].Certificate[1][0] != originalCA {
				t.Fatal("TLS snapshot borrowed certificate DER")
			}
		})
	}
}
