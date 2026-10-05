// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

func TestStoreAddCertFile(t *testing.T) {
	tests := map[string]struct {
		fixture        string
		passphrase     []byte
		wantErr        string
		wantPassphrase bool
		wantChain      int
		wantWarning    string
	}{
		"success: added file overrides generation":      {fixture: "mitmproxy-net/verificationcerts/trusted-leaf.pem", wantChain: 1},
		"success: unencrypted without passphrase":       {fixture: "mitmproxy/testkey.pem", wantChain: 1},
		"success: unencrypted ignores passphrase":       {fixture: "mitmproxy/testkey.pem", passphrase: []byte("password"), wantChain: 1},
		"success: encrypted with passphrase":            {fixture: "mitmproxy/mitmproxy.pem", passphrase: []byte("password"), wantChain: 1},
		"error: encrypted without passphrase":           {fixture: "mitmproxy/mitmproxy.pem", wantPassphrase: true},
		"error: encrypted wrong passphrase":             {fixture: "mitmproxy/mitmproxy.pem", passphrase: []byte("wrong"), wantErr: "Unable to find private key"},
		"error: no private key":                         {fixture: "mitmproxy-net/verificationcerts/trusted-leaf.crt", wantErr: "Unable to find private key"},
		"error: private and public key mismatch":        {fixture: "mitmproxy-net/verificationcerts/private-public-mismatch.pem", wantErr: "do not match"},
		"success: chain of two":                         {fixture: "mitmproxy-net/verificationcerts/trusted-chain.pem", wantChain: 2},
		"success: invalid chain falls back to the leaf": {fixture: "mitmproxy-net/verificationcerts/trusted-chain-invalid.pem", wantChain: 1, wantWarning: "Failed to read certificate chain"},
		"success: ca certificate warns":                 {fixture: "mitmproxy-net/verificationcerts/trusted-root.pem", wantChain: 1, wantWarning: "is a certificate authority and not a leaf certificate"},
		"success: server self-signed":                   {fixture: "mitmproxy/servercert/self-signed.pem", wantChain: 1},
		"success: server leaf":                          {fixture: "mitmproxy/servercert/trusted-leaf.pem", wantChain: 1},
		"success: server root":                          {fixture: "mitmproxy/servercert/trusted-root.pem", wantChain: 1},
		"success: client":                               {fixture: "mitmproxy/clientcert/client.pem", wantChain: 1},
		"success: client IP":                            {fixture: "mitmproxy/clientcert/127.0.0.1.pem", wantChain: 1},
		"error: DER certificate":                        {fixture: "mitmproxy/dercert", wantErr: "no CERTIFICATE block"},
	}
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })
	store := testStore(t)
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			path := testutil.FixturePath(t, tt.fixture)
			before := getTestCert(t, store, name, nil)
			err := store.AddCertFile(name, path, tt.passphrase)
			if tt.wantPassphrase {
				if !errors.Is(err, ErrPassphraseRequired) {
					t.Fatalf("error = %v, want ErrPassphraseRequired", err)
				}
			} else if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if err != nil {
				if after := getTestCert(t, store, name, nil); before != after {
					t.Error("failed load changed selection")
				}
				return
			}
			entry := getTestCert(t, store, name, nil)
			want, err := ParseCert(testutil.Fixture(t, tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if !entry.Cert.Equal(want) || entry == before {
				t.Error("configured certificate did not override generated entry")
			}
			if len(entry.ChainCerts) != tt.wantChain || entry.ChainFile != path {
				t.Errorf("chain = %d certificates from %q, want %d from %q", len(entry.ChainCerts), entry.ChainFile, tt.wantChain, path)
			}
			if tt.wantWarning != "" && !strings.Contains(logs.String(), tt.wantWarning) {
				t.Errorf("warning %q absent from %q", tt.wantWarning, logs.String())
			}
		})
	}
}

func TestStoreAddCertDefaultKey(t *testing.T) {
	store := testStore(t)
	leaf := getTestCert(t, store, "signed.test", nil)
	path := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(path, leaf.Cert.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.AddCertFile("default-key", path, nil); err != nil {
		t.Fatal(err)
	}
	entry := getTestCert(t, store, "default-key", nil)
	if entry.PrivateKey != store.defaultPrivateKey || !entry.Cert.Equal(leaf.Cert) {
		t.Error("matching default key was not used")
	}
	// An encrypted key without a password must not fall back even when the default key matches.
	raw := testutil.Fixture(t, "mitmproxy/mitmproxy.pem")
	key, err := loadPEMPrivateKey(raw, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	store.defaultPrivateKey = key
	if err := store.AddCertFile("encrypted", testutil.FixturePath(t, "mitmproxy/mitmproxy.pem"), nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("error = %v, want ErrPassphraseRequired", err)
	}
}

func TestStoreAddCertSpec(t *testing.T) {
	fixture := testutil.FixturePath(t, "mitmproxy/servercert/trusted-leaf.pem")
	withEquals := filepath.Join(t.TempDir(), "name=part.pem")
	if err := os.WriteFile(withEquals, testutil.Fixture(t, "mitmproxy/servercert/trusted-leaf.pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ spec, name, wantErr string }{
		"success: default wildcard":   {spec: fixture, name: "wildcard.test"},
		"success: named domain":       {spec: "named.test=" + fixture, name: "named.test"},
		"success: split first equals": {spec: "equals.test=" + withEquals, name: "equals.test"},
		"error: missing file":         {spec: "x=" + filepath.Join(t.TempDir(), "missing.pem"), wantErr: "Certificate file does not exist:"},
		"error: invalid format":       {spec: testutil.FixturePath(t, "mitmproxy/dercert"), wantErr: "Invalid certificate format for"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			store := testStore(t)
			err := store.AddCertSpec(tt.spec, nil)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want, err := ParseCert(testutil.Fixture(t, "mitmproxy/servercert/trusted-leaf.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if !getTestCert(t, store, tt.name, nil).Cert.Equal(want) {
				t.Error("spec did not select configured certificate")
			}
		})
	}
}

func TestStoreAddCertSpecHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, "cert.pem")
	if err := os.WriteFile(path, testutil.Fixture(t, "mitmproxy/testkey.pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := testStore(t).AddCertSpec("example.test=~/cert.pem", nil); err != nil {
		t.Fatal(err)
	}
}

func TestStoreAddCertSpecErrors(t *testing.T) {
	tests := map[string]struct {
		path           string
		wantPassphrase bool
	}{
		"error: passphrase remains distinct": {path: testutil.FixturePath(t, "mitmproxy/mitmproxy.pem"), wantPassphrase: true},
		"error: filesystem remains distinct": {path: t.TempDir()},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := testStore(t).AddCertSpec(tt.path, nil)
			if tt.wantPassphrase {
				if !errors.Is(err, ErrPassphraseRequired) {
					t.Fatalf("error = %v, want ErrPassphraseRequired", err)
				}
			} else if _, ok := errors.AsType[*os.PathError](err); !ok {
				t.Fatalf("error = %v, want filesystem error", err)
			}
			if strings.Contains(err.Error(), "Invalid certificate format") {
				t.Fatalf("non-format error wrapped as invalid format: %v", err)
			}
		})
	}
}

func TestParsePEMCertificates(t *testing.T) {
	cert, err := ParseCert(testutil.Fixture(t, "mitmproxy/testkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	valid := string(cert.PEM())
	tests := map[string]struct {
		raw   string
		count int
	}{
		"success: single certificate":                {raw: valid, count: 1},
		"success: ordered duplicate certificates":    {raw: valid + valid, count: 2},
		"success: surrounding non-certificate bytes": {raw: "prefix\n" + valid + "suffix", count: 1},
		"error: empty": {},
		"error: malformed first certificate before valid": {raw: "-----BEGIN CERTIFICATE-----\ninvalid\n" + valid},
		"error: truncated additional certificate":         {raw: valid + "-----BEGIN CERTIFICATE-----\n"},
		"error: invalid additional base64":                {raw: valid + "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n"},
		"error: invalid additional DER":                   {raw: valid + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			chain, err := parsePEMCertificates([]byte(tt.raw))
			if tt.count == 0 {
				if err == nil {
					t.Fatal("malformed chain accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(chain) != tt.count {
				t.Fatalf("chain length = %d, want %d", len(chain), tt.count)
			}
			for _, got := range chain {
				if !got.Equal(cert) {
					t.Error("chain certificate changed")
				}
			}
		})
	}
}

func TestStoreAddCertFileBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxPEMSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := testStore(t).AddCertFile("large", path, nil); err == nil || !strings.Contains(err.Error(), "exceeds 8 MiB") {
		t.Fatalf("error = %v, want input limit error", err)
	}
}
