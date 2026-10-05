// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

func TestDummyCRL(t *testing.T) {
	key, ca, err := CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		separateIssuer bool
	}{
		"success: self-signed CA":                      {},
		"success: CRL uses issuer rather than subject": {separateIssuer: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			issuer := *ca.X509()
			if tt.separateIssuer {
				issuer.Issuer = pkix.Name{CommonName: "parent CA"}
				issuer.RawIssuer, err = asn1.Marshal(issuer.Issuer.ToRDNSequence())
				if err != nil {
					t.Fatal(err)
				}
				issuer.SubjectKeyId = nil
				issuer.KeyUsage = 0
			}
			originalSubject := bytes.Clone(issuer.RawSubject)
			originalSKI := bytes.Clone(issuer.SubjectKeyId)
			originalUsage := issuer.KeyUsage
			der, err := dummyCRL(key, NewCert(&issuer))
			if err != nil {
				t.Fatal(err)
			}
			crl, err := x509.ParseRevocationList(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := crl.CheckSignatureFrom(ca.X509()); err != nil {
				t.Errorf("CRL signature: %v", err)
			}
			if !bytes.Equal(crl.RawIssuer, issuer.RawIssuer) {
				t.Error("CRL issuer differs from CA issuer")
			}
			if crl.Number.Int64() != 1000 || len(crl.RevokedCertificateEntries) != 0 || crl.SignatureAlgorithm != x509.SHA256WithRSA {
				t.Error("unexpected CRL number, entries or signature algorithm")
			}
			if got := crl.NextUpdate.Sub(crl.ThisUpdate); got != 7*24*time.Hour {
				t.Errorf("CRL validity = %v, want 7 days", got)
			}
			if !bytes.Equal(originalSubject, issuer.RawSubject) || !bytes.Equal(originalSKI, issuer.SubjectKeyId) || originalUsage != issuer.KeyUsage {
				t.Error("CRL generation mutated CA metadata")
			}
		})
	}
}
