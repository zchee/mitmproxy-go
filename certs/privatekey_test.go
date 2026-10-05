// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

func TestLoadPEMPrivateKey(t *testing.T) {
	tests := map[string]struct {
		fixture      string
		password     []byte
		wantErr      bool
		wantRequired bool
	}{
		"success: unencrypted without password":       {fixture: "mitmproxy/testkey.pem"},
		"success: unencrypted ignores password":       {fixture: "mitmproxy/testkey.pem", password: []byte("password")},
		"success: encrypted PKCS8":                    {fixture: "mitmproxy/mitmproxy.pem", password: []byte("password")},
		"success: certificate before PKCS8 key":       {fixture: "mitmproxy-net/verificationcerts/trusted-leaf.pem"},
		"error: encrypted without password":           {fixture: "mitmproxy/mitmproxy.pem", wantErr: true, wantRequired: true},
		"error: encrypted wrong password":             {fixture: "mitmproxy/mitmproxy.pem", password: []byte("wrong"), wantErr: true},
		"error: encrypted empty password is supplied": {fixture: "mitmproxy/mitmproxy.pem", password: []byte{}, wantErr: true},
		"error: certificate without key":              {fixture: "mitmproxy-net/verificationcerts/trusted-leaf.crt", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			raw := testutil.Fixture(t, tt.fixture)
			key, err := loadPEMPrivateKey(raw, tt.password)
			if (err != nil) != tt.wantErr || errors.Is(err, ErrPassphraseRequired) != tt.wantRequired {
				t.Fatalf("loadPEMPrivateKey() error = %v, wantErr %t, wantRequired %t", err, tt.wantErr, tt.wantRequired)
			}
			if err != nil {
				return
			}
			certificate, err := ParseCert(raw)
			if err != nil {
				t.Fatal(err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("key type = %T, want RSA", key)
			}
			if err := rsaKey.Validate(); err != nil {
				t.Fatal(err)
			}
			if !rsaKey.PublicKey.Equal(certificate.X509().PublicKey) {
				t.Error("private key does not match the fixture certificate")
			}
		})
	}
}

func TestLoadPEMPrivateKeyEncodings(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// The deprecated format is generated only to test loading existing files.
	legacy, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", sec1, []byte("password"), x509.PEMCipherAES256) //nolint:staticcheck // Compatibility test for existing encrypted PEM files.
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		block    *pem.Block
		password []byte
	}{
		"success: SEC1":                  {block: &pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}},
		"success: PKCS8":                 {block: &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}},
		"success: legacy encrypted SEC1": {block: legacy, password: []byte("password")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := loadPEMPrivateKey(pem.EncodeToMemory(tt.block), tt.password)
			if err != nil {
				t.Fatal(err)
			}
			if !key.Equal(parsed) {
				t.Error("loaded key differs from complete original key")
			}
		})
	}
	if _, err := loadPEMPrivateKey(pem.EncodeToMemory(legacy), nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("missing legacy password: %v", err)
	}
}

func TestPKCS8ParameterLimits(t *testing.T) {
	tests := map[string]struct {
		iterations int
		saltBytes  int
		keyLength  int
	}{
		"error: excessive iterations":    {iterations: 1_000_001, saltBytes: 8},
		"error: zero iterations":         {saltBytes: 8},
		"error: negative iterations":     {iterations: -1, saltBytes: 8},
		"error: excessive salt":          {iterations: 1, saltBytes: 1025},
		"error: incompatible key length": {iterations: 1, saltBytes: 8, keyLength: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			kdf, err := asn1.Marshal(struct {
				Salt       []byte
				Iterations int
				KeyLength  int `asn1:"optional"`
			}{make([]byte, tt.saltBytes), tt.iterations, tt.keyLength})
			if err != nil {
				t.Fatal(err)
			}
			iv, err := asn1.Marshal(make([]byte, 16))
			if err != nil {
				t.Fatal(err)
			}
			params, err := asn1.Marshal(struct {
				KDF    pkix.AlgorithmIdentifier
				Cipher pkix.AlgorithmIdentifier
			}{
				pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}, Parameters: asn1.RawValue{FullBytes: kdf}},
				pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, Parameters: asn1.RawValue{FullBytes: iv}},
			})
			if err != nil {
				t.Fatal(err)
			}
			der, err := asn1.Marshal(struct {
				Algorithm pkix.AlgorithmIdentifier
				Data      []byte
			}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, Parameters: asn1.RawValue{FullBytes: params}}, make([]byte, 16)})
			if err != nil {
				t.Fatal(err)
			}
			want := "PBKDF2 parameters exceed supported limits"
			if tt.keyLength != 0 {
				want = "PBKDF2 key length does not match cipher"
			}
			if _, err := decryptPKCS8(der, []byte("password")); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("invalid derivation parameters: error = %v, want %q before deriving a key", err, want)
			}
		})
	}
}

func TestLoadPEMPrivateKeyInvalid(t *testing.T) {
	tests := map[string]struct{ raw []byte }{
		"error: empty":                   {},
		"error: missing PEM":             {raw: []byte("not a key")},
		"error: invalid DER":             {raw: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0}})},
		"error: truncated encrypted DER": {raw: pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0x30, 0xff}})},
		"error: oversized PEM":           {raw: make([]byte, 8*1024*1024+1)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if key, err := loadPEMPrivateKey(tt.raw, []byte("password")); err == nil || key != nil {
				t.Errorf("invalid input returned key type %T, error %v", key, err)
			}
		})
	}
}
