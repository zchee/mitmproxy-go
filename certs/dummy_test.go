// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/netip"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/certs"
)

func TestDummyCert(t *testing.T) {
	key, ca, err := certs.CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		commonName   string
		organization string
		sans         []certs.GeneralName
		crlURL       string
		wantCN       string
		wantErr      bool
	}{
		"success: upstream with CA": {
			commonName: "foo.com", organization: "Foo Ltd.", wantCN: "foo.com",
			sans:   []certs.GeneralName{certs.DNSName("one.com"), certs.DNSName("two.com"), certs.DNSName("*.three.com"), certs.IPAddress(netip.MustParseAddr("127.0.0.1")), certs.DNSName("xn--bcher-kva.example")},
			crlURL: "https://example.com/example.crl",
		},
		"success: empty subject":     {},
		"success: organization only": {organization: "証明書"},
		"success: mixed names preserve order": {
			commonName: "example.com", wantCN: "example.com",
			sans: []certs.GeneralName{certs.IPAddress(netip.MustParseAddr("::1")), certs.DNSName("example.com"), certs.EmailName("user@example.com"), certs.URIName("https://example.com/path"), certs.DNSName("example.com")},
		},
		"success: 63 character CN":              {commonName: strings.Repeat("x", 63), wantCN: strings.Repeat("x", 63)},
		"success: 64 character CN omitted":      {commonName: strings.Repeat("x", 64)},
		"success: Unicode CN within byte limit": {commonName: strings.Repeat("é", 32), wantCN: strings.Repeat("é", 32)},
		"error: Unicode CN exceeds byte limit":  {commonName: strings.Repeat("é", 33), wantErr: true},
		"error: invalid name UTF-8":             {commonName: "\xff", wantErr: true},
		"error: DNS requires A-label":           {sans: []certs.GeneralName{certs.DNSName("bücher.example")}, wantErr: true},
		"error: invalid IP":                     {sans: []certs.GeneralName{certs.IPAddress(netip.Addr{})}, wantErr: true},
		"error: non-ASCII CRL URL":              {crlURL: "https://例え.com/crl", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			leaf, err := certs.DummyCert(key, ca, tt.commonName, tt.sans, tt.organization, tt.crlURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DummyCert() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			x := leaf.X509()
			if leaf.CN() != tt.wantCN || leaf.Organization() != tt.organization {
				t.Errorf("subject = %v, want CN=%q O=%q", leaf.Subject(), tt.wantCN, tt.organization)
			}
			if diff := gocmp.Diff(tt.sans, leaf.AltNames(), gocmp.Comparer(func(a, b certs.GeneralName) bool { return a == b })); diff != "" && (len(tt.sans) != 0 || len(leaf.AltNames()) != 0) {
				t.Errorf("SANs (-want +got):\n%s", diff)
			}
			if err := x.CheckSignatureFrom(ca.X509()); err != nil {
				t.Errorf("leaf signature: %v", err)
			}
			if !key.PublicKey.Equal(x.PublicKey) || !bytes.Equal(x.RawIssuer, ca.X509().RawSubject) {
				t.Error("leaf does not reuse CA public key and subject as issuer")
			}
			if got := x.NotAfter.Sub(x.NotBefore); got != 199*24*time.Hour {
				t.Errorf("validity = %v, want 199 days", got)
			}
			if x.SerialNumber.Sign() <= 0 || x.SerialNumber.BitLen() > 159 {
				t.Error("serial is not a positive 159-bit integer")
			}
			if x.SignatureAlgorithm != x509.SHA256WithRSA || x.IsCA || len(x.SubjectKeyId) != 0 || x.KeyUsage != 0 {
				t.Error("leaf has unexpected signature, CA flag, SKI, or key usage")
			}
			if !bytes.Equal(x.AuthorityKeyId, ca.X509().SubjectKeyId) {
				t.Error("leaf AKI differs from issuer SKI")
			}
			wantOIDs := []string{"2.5.29.37", "2.5.29.17", "2.5.29.35"}
			if tt.crlURL != "" {
				wantOIDs = append(wantOIDs, "2.5.29.31")
				if diff := gocmp.Diff([]string{tt.crlURL}, leaf.CRLDistributionPoints()); diff != "" {
					t.Errorf("CRL URLs (-want +got):\n%s", diff)
				}
			} else if len(leaf.CRLDistributionPoints()) != 0 {
				t.Error("unexpected CRL URL")
			}
			var gotOIDs []string
			for _, ext := range x.Extensions {
				gotOIDs = append(gotOIDs, ext.Id.String())
				wantCritical := ext.Id.String() == "2.5.29.17" && tt.wantCN == ""
				if ext.Critical != wantCritical {
					t.Errorf("extension %v critical = %t, want %t", ext.Id, ext.Critical, wantCritical)
				}
			}
			if diff := gocmp.Diff(wantOIDs, gotOIDs); diff != "" {
				t.Errorf("extension order (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDummyCertAuthorityKeyIdentifier(t *testing.T) {
	key, ca, err := certs.CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	fallback := sha1.Sum(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	tests := map[string]struct {
		ski  []byte
		want []byte
	}{
		"success: copies custom stored SKI":        {ski: []byte("custom issuer identifier"), want: []byte("custom issuer identifier")},
		"success: missing SKI falls back to SHA-1": {want: fallback[:]},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			issuer := *ca.X509()
			issuer.SubjectKeyId = tt.ski
			leaf, err := certs.DummyCert(key, certs.NewCert(&issuer), "example.com", nil, "", "")
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, leaf.X509().AuthorityKeyId); diff != "" {
				t.Errorf("AKI (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDummyCertECDSASHA256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, template, err := certs.CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	x := *template.X509()
	x.SignatureAlgorithm = x509.ECDSAWithSHA256
	x.PublicKey = key.Public()
	der, err := x509.CreateCertificate(rand.Reader, &x, &x, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, certs.NewCert(issuer), "example.com", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.X509().SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("signature = %v, want ECDSAWithSHA256", leaf.X509().SignatureAlgorithm)
	}
	if err := leaf.X509().CheckSignatureFrom(issuer); err != nil {
		t.Fatal(err)
	}
}

func TestDummyCertOpaqueSAN(t *testing.T) {
	key, ca, err := certs.CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	x := *ca.X509()
	// registeredID 1.2.3 is outside the public constructors but must survive reissuance.
	x.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 4, 0x88, 2, 0x2a, 3}}}
	der, err := x509.CreateCertificate(rand.Reader, &x, ca.X509(), key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	original, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sans := certs.NewCert(original).AltNames()
	leaf, err := certs.DummyCert(key, ca, "example.com", sans, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(sans, leaf.AltNames(), gocmp.Comparer(func(a, b certs.GeneralName) bool { return a == b })); diff != "" {
		t.Errorf("opaque SAN (-want +got):\n%s", diff)
	}
}
