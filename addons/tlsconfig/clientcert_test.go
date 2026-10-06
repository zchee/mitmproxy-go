// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

// writeKeyPair writes a certificate and its key into one PEM file, the layout
// client_certs expects, with commonName as the certificate's subject.
func writeKeyPair(t *testing.T, path, commonName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// clientHelloSNI captures a ClientHello from crypto/tls, splices sni into it
// in place of a placeholder of the same length, and returns the SNI that
// tlsparse reports, as the client TLS layer would see it.
func clientHelloSNI(t *testing.T, sni string) string {
	t.Helper()
	placeholder := bytes.Repeat([]byte{'a'}, len(sni))
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: string(placeholder), InsecureSkipVerify: true}).Handshake()
	}()
	if err := server.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	raw := bytes.Replace(buf[:n], placeholder, []byte(sni), 1)
	if !bytes.Contains(raw, []byte(sni)) {
		t.Fatalf("ClientHello does not carry %q", sni)
	}
	hello, err := tlsparse.ParseClientHello(raw)
	if err != nil || hello == nil {
		t.Fatalf("ParseClientHello = %v, %v", hello, err)
	}
	return hello.SNI()
}

// TestClientCertificateStaysInDirectory proves that a peer-chosen server
// name selects at most a basename inside the client_certs directory. Operator
// symlinks may point elsewhere; traversal from a parsed ClientHello or directly
// through clientCertificate must never select the decoy beside the directory.
func TestClientCertificateStaysInDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "client-certs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeKeyPair(t, filepath.Join(root, "secret.pem"), "outside-the-directory")
	writeKeyPair(t, filepath.Join(dir, "sub", "nested.pem"), "nested-in-a-subdirectory")
	writeKeyPair(t, filepath.Join(dir, "example.com.pem"), "example.com")

	tests := map[string]struct {
		sni       func(t *testing.T) string
		host      string
		wantCN    string
		wantEmpty bool
	}{
		"success: server name selects its file": {
			sni:    func(*testing.T) string { return "example.com" },
			host:   "192.0.2.1",
			wantCN: "example.com",
		},
		"success: operator symlink selects an external key store": {
			sni: func(t *testing.T) string {
				t.Helper()
				if err := os.Symlink(filepath.Join(root, "secret.pem"), filepath.Join(dir, "example.test.pem")); err != nil {
					t.Fatal(err)
				}
				return "example.test"
			},
			host:   "192.0.2.1",
			wantCN: "outside-the-directory",
		},
		"success: address host without a server name": {
			host:   "example.com",
			wantCN: "example.com",
		},
		"success: no file for the server name": {
			sni:       func(*testing.T) string { return "other.example" },
			host:      "example.com",
			wantEmpty: true,
		},
		"attack: zone traversal in a parsed ClientHello": {
			sni:       func(t *testing.T) string { return clientHelloSNI(t, "::1%a/../../secret") },
			host:      "example.org",
			wantEmpty: true,
		},
		"attack: zone traversal": {
			sni:       func(*testing.T) string { return "::1%a/../../secret" },
			host:      "example.org",
			wantEmpty: true,
		},
		"attack: parent directory": {
			sni:       func(*testing.T) string { return "../secret" },
			host:      "example.org",
			wantEmpty: true,
		},
		"attack: absolute path": {
			sni:       func(*testing.T) string { return filepath.Join(root, "secret") },
			host:      "example.org",
			wantEmpty: true,
		},
		"attack: subdirectory": {
			sni:       func(*testing.T) string { return "sub/nested" },
			host:      "example.org",
			wantEmpty: true,
		},
		"attack: address host traversal": {
			host:      "../secret",
			wantEmpty: true,
		},
		"attack: NUL in the name": {
			sni:       func(*testing.T) string { return "example.com\x00" },
			host:      "example.org",
			wantEmpty: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := connection.NewServer(&connection.Address{Host: tt.host, Port: 443})
			if tt.sni != nil {
				sni := tt.sni(t)
				server.SNI = &sni
			}
			cert, err := clientCertificate(dir, server)
			if err != nil {
				t.Fatalf("clientCertificate error: %v", err)
			}
			if tt.wantEmpty {
				if cert != nil {
					leaf, _ := x509.ParseCertificate(cert.Certificate[0])
					t.Fatalf("loaded a client certificate (CN=%q), want none", leaf.Subject.CommonName)
				}
				return
			}
			if cert == nil {
				t.Fatal("no client certificate loaded")
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if leaf.Subject.CommonName != tt.wantCN {
				t.Fatalf("loaded CN=%q, want %q", leaf.Subject.CommonName, tt.wantCN)
			}
		})
	}
}
