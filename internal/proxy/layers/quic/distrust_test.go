// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

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

	quicgo "github.com/quic-go/quic-go"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/options"
)

type distrustSettings struct{ table certs.CADistrust }

func (d *distrustSettings) QUICStartServer(_ context.Context, data *hookdata.QUICTLS) error {
	if data.Settings == nil {
		return fmt.Errorf("tlsconfig did not supply settings")
	}
	insecure := data.Settings.VerifyMode != nil && *data.Settings.VerifyMode == hookdata.VerifyNone
	if (data.Settings.VerifyConnection == nil) != insecure {
		return fmt.Errorf("tlsconfig did not honor the verification mode")
	}
	// Inject only owned identities at the same immutable callback boundary.
	// Even an addon-supplied callback must not run for VerifyNone.
	data.Settings.VerifyConnection = d.table.VerifyConnection
	return nil
}

func distrustOrigin(t *testing.T) (*tls.Config, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	var parent *x509.Certificate
	var parentKey *ecdsa.PrivateKey
	var root, intermediate *x509.Certificate
	var wire tls.Certificate
	for index := range 3 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 1)), Subject: pkix.Name{CommonName: "owned synthetic CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: index < 2, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, DNSNames: []string{"origin.test"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
			wire = tls.Certificate{Certificate: [][]byte{der, intermediate.Raw}, PrivateKey: key}
		}
		parent, parentKey = certificate, key
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{wire}}, root, intermediate
}

func TestUpstreamCADistrust(t *testing.T) {
	origin, root, intermediate := distrustOrigin(t)
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
			var table certs.CADistrust
			if test.blocked != nil {
				var err error
				table, err = certs.ParseCADistrust(fmt.Sprintf("%X", sha256.Sum256(test.blocked.Raw)))
				if err != nil {
					t.Fatal(err)
				}
			}
			opts := options.New()
			manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
			defer manager.Close()
			if err := manager.Add(t.Context(), tlsconfig.New(opts), &distrustSettings{table: table}); err != nil {
				t.Fatal(err)
			}
			trust := filepath.Join(t.TempDir(), "root.pem")
			if err := os.WriteFile(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"ssl_verify_upstream_trusted_ca": trust, "ssl_insecure": test.insecure})
			}); err != nil {
				t.Fatal(err)
			}
			c := &layer.Context{Data: &hookdata.Context{Client: connection.NewClient(connection.Address{}, connection.Address{}, 0), Server: connection.NewServer(&connection.Address{Host: "origin.test", Port: 443}), Options: opts}, Do: manager.Do, Hooks: &proxy.HookRunner{Manager: manager}}
			policy, err := startPolicy(t.Context(), c, false)
			if err != nil {
				t.Fatal(err)
			}
			config, err := policy.config(false)
			if err != nil {
				t.Fatal(err)
			}
			if (config.VerifyConnection == nil) != test.insecure {
				t.Fatal("verification callback lost or installed in insecure mode")
			}
			serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = serverSocket.Close() }()
			serverTransport := &quicgo.Transport{Conn: serverSocket}
			defer func() { _ = serverTransport.Close() }()
			listener, err := serverTransport.Listen(origin, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = clientSocket.Close() }()
			clientTransport := &quicgo.Transport{Conn: clientSocket}
			defer func() { _ = clientTransport.Close() }()
			client, err := clientTransport.Dial(ctx, listener.Addr(), config, nil)
			if test.wantError {
				if client != nil {
					_ = client.CloseWithError(0, "")
				}
				if err == nil || !strings.Contains(err.Error(), "explicitly distrusted") {
					t.Fatalf("explicit rejection = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unrelated/insecure QUIC handshake: %v", err)
			}
			defer func() { _ = client.CloseWithError(0, "") }()
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.CloseWithError(0, "") }()
			if len(client.ConnectionState().TLS.PeerCertificates) != 2 {
				t.Fatal("fixture unexpectedly sent its trust anchor")
			}
		})
	}
}
