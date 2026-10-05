// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func tlsConfigs(t testing.TB) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	server := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
	client := &tls.Config{RootCAs: roots, ServerName: "example.com"}
	return server, client
}

type closeTrace struct {
	layer.Conn
	events []string
}

func (c *closeTrace) Write(p []byte) (int, error) {
	if len(p) != 0 && p[0] == 21 {
		c.events = append(c.events, "TLS alert")
	}
	return c.Conn.Write(p)
}

func (c *closeTrace) CloseWrite() error {
	c.events = append(c.events, "FIN")
	return c.Conn.CloseWrite()
}

func TestTLSCloseWrite(t *testing.T) {
	tests := map[string]struct{ server bool }{"client": {}, "server": {server: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConfig, clientConfig := tlsConfigs(t)
			// TLS 1.2 leaves the record content type visible, so the transport
			// can independently observe an alert preceding the FIN.
			serverConfig.MaxVersion, clientConfig.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			raw, peerRaw := layertest.Pipe(t)
			trace := &closeTrace{Conn: raw}
			local, peer := tls.Client(trace, clientConfig), tls.Server(peerRaw, serverConfig)
			if tt.server {
				local, peer = tls.Server(trace, serverConfig), tls.Client(peerRaw, clientConfig)
			}
			done := make(chan error, 1)
			go func() { done <- peer.HandshakeContext(t.Context()) }()
			if err := local.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			conn := &tlsConn{Conn: local, raw: trace}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"TLS alert", "FIN"}, trace.events); diff != "" {
				t.Errorf("shutdown order (-want +got):\n%s", diff)
			}
			var buf [1]byte
			if _, err := peer.Read(buf[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("decrypted EOF: %v", err)
			}
			if _, err := peerRaw.Read(buf[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("raw FIN after close_notify: %v", err)
			}
			if _, err := peer.Write([]byte("response")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("response"))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != "response" {
				t.Fatalf("read after half-close = %q", got)
			}
		})
	}
}
