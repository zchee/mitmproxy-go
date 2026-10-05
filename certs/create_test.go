// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/certs"
)

func TestCreateCA(t *testing.T) {
	// The fields and extension encodings follow mitmproxy.certs.create_ca.
	tests := map[string]struct {
		organization string
		commonName   string
		keySize      int
		wantErr      bool
	}{
		"success: default names":                {organization: "mitmproxy", commonName: "mitmproxy", keySize: 2048},
		"success: Unicode names":                {organization: "証明書", commonName: "例え", keySize: 1024},
		"error: small RSA key":                  {organization: "mitmproxy", commonName: "mitmproxy", keySize: 512, wantErr: true},
		"error: invalid UTF-8":                  {organization: "mitmproxy", commonName: "\xff", keySize: 1024, wantErr: true},
		"success: maximum common name bytes":    {organization: "", commonName: strings.Repeat("é", 32), keySize: 1024},
		"success: long organization":            {organization: strings.Repeat("o", 65), commonName: "mitmproxy", keySize: 1024},
		"error: empty common name":              {organization: "mitmproxy", keySize: 1024, wantErr: true},
		"error: common name exceeds byte limit": {organization: "mitmproxy", commonName: strings.Repeat("é", 33), keySize: 1024, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			key, ca, err := certs.CreateCA(tt.organization, tt.commonName, tt.keySize)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CreateCA() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err != nil {
				if key != nil || ca != nil {
					t.Fatal("CreateCA returned a partial result with an error")
				}
				return
			}
			x := ca.X509()
			if key.N.BitLen() != tt.keySize || key.E != 65537 || !key.PublicKey.Equal(x.PublicKey) {
				t.Error("certificate public key does not match requested RSA key")
			}
			if err := x.CheckSignatureFrom(x); err != nil {
				t.Fatalf("self signature: %v", err)
			}
			if x.Version != 3 || x.SignatureAlgorithm != x509.SHA256WithRSA || !x.IsCA || x.MaxPathLen != -1 {
				t.Errorf("CA properties: version=%d signature=%v isCA=%t pathLen=%d", x.Version, x.SignatureAlgorithm, x.IsCA, x.MaxPathLen)
			}
			if x.SerialNumber.Sign() <= 0 || x.SerialNumber.BitLen() > 159 {
				t.Errorf("serial must be positive and at most 159 bits: %v", x.SerialNumber)
			}
			if got := x.NotAfter.Sub(x.NotBefore); got != 3650*24*time.Hour {
				t.Errorf("validity = %v, want 3650 days", got)
			}
			if !bytes.Equal(x.RawSubject, x.RawIssuer) {
				t.Error("CA issuer differs from subject")
			}
			wantName := []certs.KeyVal{{Key: "CN", Value: tt.commonName}, {Key: "O", Value: tt.organization}}
			if diff := gocmp.Diff(wantName, ca.Subject()); diff != "" {
				t.Errorf("subject (-want +got):\n%s", diff)
			}
			type nameAttributeSET []struct {
				OID   asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			var rdns []nameAttributeSET
			if _, err := asn1.Unmarshal(x.RawSubject, &rdns); err != nil {
				t.Fatal(err)
			}
			for _, rdn := range rdns {
				if rdn[0].Value.Tag != asn1.TagUTF8String {
					t.Errorf("name string tag = %d, want UTF8String", rdn[0].Value.Tag)
				}
			}
			ski := sha1.Sum(x509.MarshalPKCS1PublicKey(&key.PublicKey))
			wantExtensions := []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 3, 1, 1, 0xff}},
				{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 10, 6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 1}},
				{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{3, 2, 1, 6}},
				{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: append([]byte{4, 20}, ski[:]...)},
			}
			if diff := gocmp.Diff(wantExtensions, x.Extensions); diff != "" {
				t.Errorf("extensions (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCreateCAIndependentMaterial(t *testing.T) {
	firstKey, first, err := certs.CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, second, err := certs.CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if firstKey.Equal(secondKey) || first.Serial().Cmp(second.Serial()) == 0 {
		t.Fatal("independently created CAs reused private key or serial")
	}
	if err := firstKey.Validate(); err != nil {
		t.Fatalf("RSA private key: %v", err)
	}
	if _, ok := first.X509().PublicKey.(*rsa.PublicKey); !ok {
		t.Fatal("CA public key is not RSA")
	}
}
