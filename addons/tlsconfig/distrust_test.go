// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/options"
)

func distrustChain(t *testing.T) (tls.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	var parent *x509.Certificate
	var parentKey *ecdsa.PrivateKey
	var wire tls.Certificate
	var root, intermediate *x509.Certificate
	for index := range 3 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 1)), Subject: pkix.Name{CommonName: "owned synthetic CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: index < 2, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, DNSNames: []string{"origin.test"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if parent == nil {
			parent, parentKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		switch index {
		case 0:
			root = certificate
		case 1:
			intermediate = certificate
		case 2:
			wire = tls.Certificate{Certificate: [][]byte{der, intermediate.Raw}, PrivateKey: key, Leaf: certificate}
		}
		parent, parentKey = certificate, key
	}
	return wire, root, intermediate
}

func TestUpstreamCADistrust(t *testing.T) {
	wire, root, intermediate := distrustChain(t)
	paths := map[string]struct{ dtls bool }{"tls": {}, "dtls": {dtls: true}}
	for path, transport := range paths {
		t.Run(path, func(t *testing.T) {
			tests := map[string]struct {
				blocked   *x509.Certificate
				insecure  bool
				wantError bool
			}{
				"affected_intermediate_rejected": {blocked: intermediate, wantError: true},
				"affected_trust_anchor_rejected": {blocked: root, wantError: true},
				"unrelated_chain_accepted":       {},
				"ssl_insecure_passthrough":       {blocked: intermediate, insecure: true},
			}
			for name, test := range tests {
				t.Run(name, func(t *testing.T) {
					opts := options.New()
					security := New(opts)
					if test.blocked != nil {
						var err error
						security.distrustedCAs, err = certs.ParseCADistrust(fmt.Sprintf("%X", sha256.Sum256(test.blocked.Raw)))
						if err != nil {
							t.Fatal(err)
						}
					}
					manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
					t.Cleanup(manager.Close)
					if err := manager.Add(t.Context(), security); err != nil {
						t.Fatal(err)
					}
					trust := filepath.Join(t.TempDir(), "root.pem")
					if err := os.WriteFile(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := configure(t, manager, opts, map[string]any{"ssl_verify_upstream_trusted_ca": trust, "ssl_insecure": test.insecure}); err != nil {
						t.Fatal(err)
					}
					c := testContext(opts)
					c.Server.Address = &connection.Address{Host: "origin.test", Port: 443}
					data := &hookdata.TLS{Context: c, Conn: &c.Server.Connection, IsDTLS: transport.dtls}
					if err := manager.Hook(t.Context(), addon.TLSStartServerHook{Data: data}); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancel()
					var err error
					if transport.dtls {
						err = distrustDTLSHandshake(t, ctx, data.DTLSConfig, wire)
					} else {
						err = distrustTLSHandshake(t, ctx, data.Config, wire)
					}
					if test.wantError {
						if err == nil || !strings.Contains(err.Error(), "explicitly distrusted") {
							t.Fatalf("%s did not reject the explicitly distrusted identity: %v", path, err)
						}
					} else if err != nil {
						t.Fatalf("%s handshake: %v", path, err)
					}
				})
			}
		})
	}
	t.Run("unrelated_revocation_requests_unchanged", func(t *testing.T) {
		security, manager, _ := newTLSConfig(t)
		for _, request := range []*httpmsg.Request{
			{Host: "ocsp-a.emsign.com", Path: "/ordinary-ocsp"},
			{Host: "crl.comodoca.com", Path: "/ordinary.crl"},
			{Host: "unrelated.test", Path: "/ordinary.crl"},
		} {
			f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 0), connection.NewServer(nil), true)
			f.Live, f.Request = true, request
			if err := manager.Do(t.Context(), func(ctx context.Context) error { return security.Request(ctx, f) }); err != nil {
				t.Fatal(err)
			}
			if f.Error != nil || f.Response != nil {
				t.Fatalf("ordinary revocation request altered: %+v", f)
			}
		}
		f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 0), connection.NewServer(nil), true)
		f.Live, f.Request = true, &httpmsg.Request{Host: "unrelated.test", Path: security.crlPath()}
		if err := manager.Do(t.Context(), func(ctx context.Context) error { return security.Request(ctx, f) }); err != nil {
			t.Fatal(err)
		}
		if f.Error != nil || f.Response == nil || string(f.Response.RawContent) != string(security.store.DefaultCRL()) {
			t.Fatal("magic CRL substitution changed")
		}
	})
}

func distrustTLSHandshake(t *testing.T, ctx context.Context, config *tls.Config, certificate tls.Certificate) error {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		done <- server.HandshakeContext(ctx)
	}()
	client, err := (&tls.Dialer{Config: config}).DialContext(ctx, "tcp4", listener.Addr().String())
	if client != nil {
		_ = client.Close()
	}
	_ = listener.Close()
	serverErr := <-done
	if err == nil && serverErr != nil {
		return fmt.Errorf("origin handshake: %w", serverErr)
	}
	return err
}

func distrustDTLSHandshake(t *testing.T, ctx context.Context, config *dtls.Config, certificate tls.Certificate) error { //nolint:staticcheck // Exercise the hook's mutable DTLS configuration contract.
	t.Helper()
	serverPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverPacket.Close() }()
	clientPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientPacket.Close() }()
	server, err := dtls.Server(serverPacket, clientPacket.LocalAddr(), &dtls.Config{Certificates: []tls.Certificate{certificate}}) //nolint:staticcheck // Match the hook's DTLS transport API.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	client, err := dtls.Client(clientPacket, serverPacket.LocalAddr(), config) //nolint:staticcheck // Match the hook's DTLS transport API.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(ctx) }()
	err = client.HandshakeContext(ctx)
	if err != nil {
		cancel()
	}
	serverErr := <-done
	if err == nil && serverErr != nil {
		return fmt.Errorf("origin handshake: %w", serverErr)
	}
	return err
}
