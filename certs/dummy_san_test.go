// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/netip"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/certs"
)

func TestDummyCertSAN(t *testing.T) {
	key, ca, err := certs.CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	// registeredID is opaque to the public name constructors.
	opaqueDER := []byte{0x30, 4, 0x88, 2, 0x2a, 3}
	template := *ca.X509()
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: opaqueDER}}
	der, err := x509.CreateCertificate(rand.Reader, &template, ca.X509(), key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	opaqueNames := certs.NewCert(opaque).AltNames()
	if len(opaqueNames) != 1 || opaqueNames[0].Type() != certs.GeneralNameOther {
		t.Fatalf("opaque fixture SANs = %v, want one unmodelled name", opaqueNames)
	}
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			commonName   string
			organization string
			sans         []certs.GeneralName
			wantCN       string
			store        bool
		}{
			"nil_names":                 {organization: "Example"},
			"empty_names":               {sans: []certs.GeneralName{}, organization: "Example"},
			"named_cn_without_san":      {commonName: "example.com", wantCN: "example.com"},
			"empty_subject_without_san": {},
			"overlong_cn_without_san":   {commonName: strings.Repeat("x", 64)},
			"nonempty_dns":              {commonName: "example.com", wantCN: "example.com", sans: []certs.GeneralName{certs.DNSName("example.com")}},
			"nonempty_ip":               {organization: "Example", sans: []certs.GeneralName{certs.IPAddress(netip.MustParseAddr("::1"))}},
			"nonempty_opaque":           {commonName: strings.Repeat("x", 64), sans: opaqueNames},
			"store_without_san":         {commonName: "example.com", wantCN: "example.com", store: true},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				const crlURL = "https://example.com/issuer.crl"
				leaf, err := certs.DummyCert(key, ca, tt.commonName, tt.sans, tt.organization, crlURL)
				if err != nil {
					t.Fatal(err)
				}
				if leaf.CN() != tt.wantCN || leaf.Organization() != tt.organization {
					t.Errorf("subject = %v, want CN=%q O=%q", leaf.Subject(), tt.wantCN, tt.organization)
				}
				wantOIDs := []string{"2.5.29.37"}
				if len(tt.sans) > 0 {
					wantOIDs = append(wantOIDs, "2.5.29.17")
				}
				wantOIDs = append(wantOIDs, "2.5.29.35", "2.5.29.31")
				var gotOIDs []string
				for _, ext := range leaf.X509().Extensions {
					gotOIDs = append(gotOIDs, ext.Id.String())
					wantCritical := ext.Id.String() == "2.5.29.17" && tt.wantCN == ""
					if ext.Critical != wantCritical {
						t.Errorf("extension %v critical = %t, want %t", ext.Id, ext.Critical, wantCritical)
					}
					if name == "nonempty_opaque" && ext.Id.String() == "2.5.29.17" {
						if diff := gocmp.Diff(opaqueDER, ext.Value); diff != "" {
							t.Errorf("opaque SAN DER (-want +got):\n%s", diff)
						}
					}
				}
				if diff := gocmp.Diff(wantOIDs, gotOIDs); diff != "" {
					t.Errorf("extension order (-want +got):\n%s", diff)
				}
				gotNames := leaf.AltNames()
				if len(tt.sans) != 0 || len(gotNames) != 0 {
					if diff := gocmp.Diff(tt.sans, gotNames, gocmp.Comparer(func(a, b certs.GeneralName) bool { return a == b })); diff != "" {
						t.Errorf("SANs (-want +got):\n%s", diff)
					}
				}
				if err := leaf.X509().CheckSignatureFrom(ca.X509()); err != nil {
					t.Errorf("leaf signature: %v", err)
				}
				if tt.store {
					store := new(certs.Store)
					entry := &certs.Entry{Cert: leaf, PrivateKey: key}
					store.AddCert(entry, "alias.example")
					for _, lookup := range []string{tt.wantCN, "alias.example"} {
						got, err := store.GetCert(lookup, nil, "", "")
						if err != nil || got != entry {
							t.Errorf("GetCert(%q) = %p, %v; want registered entry %p", lookup, got, err, entry)
						}
					}
					if _, err := store.GetCert("", nil, "", ""); err == nil {
						t.Error("SAN-less certificate unexpectedly indexed under an empty name")
					}
				}
			})
		}
	})
}
