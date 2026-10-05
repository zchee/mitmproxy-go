// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

func fixtureCert(t *testing.T, name string) *certs.Cert {
	t.Helper()
	c, err := certs.ParseCert(testutil.Fixture(t, name))
	if err != nil {
		t.Fatalf("ParseCert(%s): %v", name, err)
	}
	return c
}

func TestParseCert(t *testing.T) {
	fixture := testutil.Fixture(t, "mitmproxy-net/text_cert_2")
	tests := map[string]struct {
		data    []byte
		wantErr bool
	}{
		"error: empty":                    {wantErr: true},
		"error: missing certificate":      {data: []byte("not PEM"), wantErr: true},
		"error: invalid DER":              {data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0xff}}), wantErr: true},
		"error: truncated PEM":            {data: fixture[:len(fixture)/2], wantErr: true},
		"success: certificate":            {data: fixture},
		"success: first certificate only": {data: bytes.Repeat(fixture, 2)},
		"success: skip other block":       {data: append(pem.EncodeToMemory(&pem.Block{Type: "OTHER", Bytes: []byte("other")}), fixture...)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := certs.ParseCert(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseCert error = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil && c.CN() != "www.inode.co.nz" {
				t.Errorf("CN() = %q, want www.inode.co.nz", c.CN())
			}
		})
	}
}

func TestCertSimple(t *testing.T) {
	c1 := fixtureCert(t, "mitmproxy-net/text_cert")
	c2 := fixtureCert(t, "mitmproxy-net/text_cert_2")
	if c1.CN() != "google.com" || len(c1.AltNames()) != 436 || c1.Organization() != "Google Inc" {
		t.Errorf("google certificate: CN=%q, SAN count=%d, O=%q", c1.CN(), len(c1.AltNames()), c1.Organization())
	}
	if c2.CN() != "www.inode.co.nz" || len(c2.AltNames()) != 2 {
		t.Errorf("inode certificate: CN=%q, SAN count=%d", c2.CN(), len(c2.AltNames()))
	}
	if want := time.Date(2010, 1, 11, 19, 27, 36, 0, time.UTC); c2.NotBefore() != want {
		t.Errorf("NotBefore() = %v, want %v", c2.NotBefore(), want)
	}
	if want := time.Date(2011, 1, 12, 9, 14, 55, 0, time.UTC); c2.NotAfter() != want {
		t.Errorf("NotAfter() = %v, want %v", c2.NotAfter(), want)
	}
	if want := "<Cert(cn='www.inode.co.nz', altnames=['www.inode.co.nz', 'inode.co.nz'])>"; c2.String() != want {
		t.Errorf("String() = %q, want %q", c2.String(), want)
	}
	if c1.Equal(c2) || c1.Equal(nil) {
		t.Error("distinct certificates compare equal")
	}
	if got, want := c2.Fingerprint(), sha256.Sum256(c2.X509().Raw); got != want {
		t.Errorf("Fingerprint() = %x, want %x", got, want)
	}
	if len(c2.Subject()) == 0 || len(c2.Issuer()) == 0 || c2.Serial().Sign() <= 0 || !c2.HasExpired() {
		t.Error("expected nonempty names, positive serial and expired validity for inode certificate")
	}
}

func TestCertConvert(t *testing.T) {
	c := fixtureCert(t, "mitmproxy-net/text_cert")
	copy, err := certs.ParseCert(c.PEM())
	if err != nil {
		t.Fatal(err)
	}
	if c == copy || !c.Equal(copy) || !c.Equal(certs.NewCert(c.X509())) {
		t.Error("PEM round trip must create a distinct, equal certificate")
	}
	if diff := gocmp.Diff(c.PEM(), copy.PEM()); diff != "" {
		t.Errorf("PEM round trip (-want +got):\n%s", diff)
	}
}

func TestCertKeyInfo(t *testing.T) {
	tests := map[string]struct {
		file      string
		algorithm string
		bits      int
	}{
		"RSA": {file: "text_cert", algorithm: "RSA", bits: 1024},
		"DSA": {file: "dsa_cert.pem", algorithm: "DSA", bits: 1024},
		"EC":  {file: "ec_cert.pem", algorithm: "EC (secp256r1)", bits: 256},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := fixtureCert(t, "mitmproxy-net/"+tt.file)
			algorithm, bits := c.KeyInfo()
			if algorithm != tt.algorithm || bits != tt.bits {
				t.Errorf("KeyInfo() = (%q, %d), want (%q, %d)", algorithm, bits, tt.algorithm, tt.bits)
			}
		})
	}
}

func TestCertIsCA(t *testing.T) {
	tests := map[string]struct {
		file string
		isCA bool
	}{
		"leaf":                 {file: "mitmproxy-net/verificationcerts/trusted-leaf.crt"},
		"root":                 {file: "mitmproxy-net/verificationcerts/trusted-root.crt", isCA: true},
		"no basic constraints": {file: "mitmproxy/invalid-subject.pem"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := fixtureCert(t, tt.file).IsCA(); got != tt.isCA {
				t.Errorf("IsCA() = %t, want %t", got, tt.isCA)
			}
		})
	}
}

func TestCertAltNames(t *testing.T) {
	tests := map[string]struct {
		file string
		want []certs.GeneralName
	}{
		"success: dns names in certificate order": {
			file: "mitmproxy-net/text_cert_2",
			want: []certs.GeneralName{certs.DNSName("www.inode.co.nz"), certs.DNSName("inode.co.nz")},
		},
		"success: non-DNS SAN remains available": {
			file: "mitmproxy-net/text_cert_weird1",
			want: []certs.GeneralName{certs.EmailName("wwwadmin@uni-muenster.de")},
		},
		"success: no SAN": {file: "mitmproxy/invalid-subject.pem", want: []certs.GeneralName{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := fixtureCert(t, tt.file).AltNames()
			if diff := gocmp.Diff(tt.want, got, gocmp.Comparer(func(a, b certs.GeneralName) bool { return a == b })); diff != "" {
				t.Errorf("AltNames() (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCertSubjectIssuer(t *testing.T) {
	t.Run("success: comma in the organization", func(t *testing.T) {
		c := fixtureCert(t, "mitmproxy-net/text_cert_with_comma")
		tests := map[string]struct {
			attrs []certs.KeyVal
			want  string
		}{
			"subject": {attrs: c.Subject(), want: "GitHub, Inc."},
			"issuer":  {attrs: c.Issuer(), want: "DigiCert, Inc."},
		}
		for name, tt := range tests {
			var org string
			for _, attr := range tt.attrs {
				if attr.Key == "O" {
					org = attr.Value
				}
			}
			if org != tt.want {
				t.Errorf("%s O = %q, want %q", name, org, tt.want)
			}
		}
	})
	t.Run("success: missing common name", func(t *testing.T) {
		c := fixtureCert(t, "mitmproxy/no_common_name.pem")
		if c.CN() != "" {
			t.Errorf("CN() = %q, want empty", c.CN())
		}
		if !bytes.HasPrefix([]byte(c.String()), []byte("<Cert(cn=None,")) {
			t.Errorf("String() = %q, want None for missing CN", c.String())
		}
	})
}

func TestCertCRLDistributionPoints(t *testing.T) {
	tests := map[string]struct {
		file string
		want []string
	}{
		"with crl":        {file: "trusted-leaf.crt", want: []string{"https://trusted-root/example.crl"}},
		"invalid crl URI": {file: "invalid-crl.crt", want: []string{"//["}},
		"without crl":     {file: "trusted-root.crt", want: []string{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := fixtureCert(t, "mitmproxy-net/verificationcerts/"+tt.file).CRLDistributionPoints()
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("CRLDistributionPoints() (-want +got):\n%s", diff)
			}
		})
	}
}
