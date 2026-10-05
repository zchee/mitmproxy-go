// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs_test

// Upstream test port map, test/mitmproxy/test_certs.py at the pinned
// commit. Each upstream test function maps to one Go case, or is listed
// as not applicable with the reason.
//
//	TestCertStore.test_create_explicit               -> TestFromStore/"success: creating then loading keeps the CA"
//	TestCertStore.test_create_no_common_name         -> TestStoreGetCert/"success: no common name"
//	TestCertStore.test_chain_file                    -> TestFromStore/"success: chain file only when more than one certificate"
//	TestCertStore.test_sans                          -> TestStoreGetCert/"success: sans do not alias unrelated names"
//	TestCertStore.test_sans_change                   -> TestStoreGetCert/"success: new sans generate a new certificate"
//	TestCertStore.test_expire                        -> TestStoreExpire
//	TestCertStore.test_create_dhparams               -> TestFromStore/"success: missing dhparam file is recreated"
//	TestCertStore.test_umask_secret                  -> TestFromStoreFileModes (unix-only; Windows has no file mode bits, so the mode assertions are skipped there and the file contents are still checked)
//	TestCertStore.test_asterisk_forms                -> TestAsteriskForms
//	TestDummyCert.test_validity_period               -> TestDummyCert/"success: validity period"
//	TestDummyCert.test_with_ca                       -> TestDummyCert/"success: names, organization and crl"
//	TestDummyCert.test_aki_copies_issuer_ski_non_sha1 -> TestDummyCert/"success: aki copies a non-sha1 issuer ski"
//	TestDummyCert.test_aki_falls_back_when_issuer_has_no_ski -> TestDummyCert/"success: aki from public key when the issuer has no ski"
//	TestCert.test_simple                             -> TestCertSimple
//	TestCert.test_convert                            -> TestCertConvert (the pyOpenSSL round trip is not applicable: the port has no pyOpenSSL objects; the PEM and state round trips are ported)
//	TestCert.test_keyinfo                            -> TestCertKeyInfo
//	TestCert.test_is_ca                              -> TestCertIsCA
//	TestCert.test_err_broken_sans                    -> TestCertAltNames/"success: non-DNS SAN remains available"
//	TestCert.test_state                              -> TestCertConvert (state is the PEM; the copy half is covered by parsing the PEM twice)
//	TestCert.test_add_cert_overrides                 -> TestStoreAddCertFile/"success: added file overrides generation"
//	TestCert.test_from_store_with_passphrase         -> TestStoreAddCertFile passphrase cases
//	TestCert.test_add_cert_with_no_private_key       -> TestStoreAddCertFile/"error: no private key"
//	TestCert.test_add_cert_private_public_mismatch   -> TestStoreAddCertFile/"error: private and public key mismatch"
//	TestCert.test_add_cert_chain                     -> TestStoreAddCertFile/"success: chain of two"
//	TestCert.test_add_cert_chain_invalid             -> TestStoreAddCertFile/"success: invalid chain falls back to the leaf"
//	TestCert.test_add_cert_is_ca                     -> TestStoreAddCertFile/"success: ca certificate warns"
//	TestCert.test_special_character                  -> TestCertSubjectIssuer/"success: comma in the organization"
//	TestCert.test_multi_valued_rdns                  -> TestParseNameMultivaluedRDN
//	TestCert.test_crl_distribution_points            -> TestCertCRLDistributionPoints
//	TestDNTree (commented out upstream)              -> not applicable: dead code at the pinned commit.

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// TestDefaultDHParam checks the constant against the upstream-generated
// configuration directory fixture, which upstream wrote from the same
// constant.
func TestDefaultDHParam(t *testing.T) {
	want := testutil.Fixture(t, "mitmproxy/confdir/mitmproxy-dhparam.pem")
	if diff := gocmp.Diff(string(want), certs.DefaultDHParam); diff != "" {
		t.Errorf("DefaultDHParam differs from the upstream file (-upstream +got):\n%s", diff)
	}
}

func TestExpiryConstants(t *testing.T) {
	tests := map[string]struct {
		got  float64
		want float64
	}{
		"CAExpiry is 10*365 days":   {got: certs.CAExpiry.Hours(), want: 10 * 365 * 24},
		"CertExpiry is 199 days":    {got: certs.CertExpiry.Hours(), want: 199 * 24},
		"CRLExpiry is 7 days":       {got: certs.CRLExpiry.Hours(), want: 7 * 24},
		"ValidityOffset is -2 days": {got: certs.ValidityOffset.Hours(), want: -2 * 24},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v hours, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestGeneralName(t *testing.T) {
	tests := map[string]struct {
		name       certs.GeneralName
		wantType   certs.GeneralNameType
		wantString string
	}{
		"success: dns": {
			name:       certs.DNSName("*.example.com"),
			wantType:   certs.GeneralNameDNS,
			wantString: "*.example.com",
		},
		"success: idna dns stays encoded": {
			name:       certs.DNSName("xn--bcher-kva.example"),
			wantType:   certs.GeneralNameDNS,
			wantString: "xn--bcher-kva.example",
		},
		"success: ipv4": {
			name:       certs.IPAddress(netip.MustParseAddr("127.0.0.1")),
			wantType:   certs.GeneralNameIP,
			wantString: "127.0.0.1",
		},
		"success: ipv6": {
			name:       certs.IPAddress(netip.MustParseAddr("2001:db8::1")),
			wantType:   certs.GeneralNameIP,
			wantString: "2001:db8::1",
		},
		"success: uri": {
			name:       certs.URIName("https://example.com/example.crl"),
			wantType:   certs.GeneralNameURI,
			wantString: "https://example.com/example.crl",
		},
		"success: email": {
			name:       certs.EmailName("user@example.com"),
			wantType:   certs.GeneralNameEmail,
			wantString: "user@example.com",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.name.Type(); got != tt.wantType {
				t.Errorf("Type() = %v, want %v", got, tt.wantType)
			}
			if got := tt.name.String(); got != tt.wantString {
				t.Errorf("String() = %q, want %q", got, tt.wantString)
			}
		})
	}
}

// TestGeneralNameComparable checks that equal names compare equal with
// ==, which the store's generated-certificate keys rely on.
func TestGeneralNameComparable(t *testing.T) {
	a, b := certs.DNSName("a.example"), certs.DNSName("a"+".example")
	if a != b {
		t.Error("equal DNS names are not ==")
	}
	if certs.DNSName("127.0.0.1") == certs.IPAddress(netip.MustParseAddr("127.0.0.1")) {
		t.Error("a DNS name equals an IP name with the same text")
	}
	if certs.URIName("x") == certs.EmailName("x") {
		t.Error("a URI name equals an email name with the same text")
	}
}

// TestCertTrivial exercises the accessors that read the parsed
// certificate directly, over the DER fixture.
func TestCertTrivial(t *testing.T) {
	x, err := x509.ParseCertificate(testutil.Fixture(t, "mitmproxy/dercert"))
	if err != nil {
		t.Fatalf("parse dercert: %v", err)
	}
	c := certs.NewCert(x)

	if c.X509() != x {
		t.Error("X509() does not return the wrapped certificate")
	}
	if got := c.Serial(); got.Sign() <= 0 {
		t.Errorf("Serial() = %v, want a positive serial", got)
	}
	if !c.NotBefore().Before(c.NotAfter()) {
		t.Errorf("NotBefore() %v is not before NotAfter() %v", c.NotBefore(), c.NotAfter())
	}
	if loc := c.NotBefore().Location(); loc != time.UTC {
		t.Errorf("NotBefore() location = %v, want UTC", loc)
	}
	if !c.HasExpired() {
		t.Error("HasExpired() = false for a certificate from 2013")
	}
	if c.IsCA() {
		t.Error("IsCA() = true for a leaf certificate")
	}

	reparsed, err := x509.ParseCertificate(x.Raw)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if !c.Equal(certs.NewCert(reparsed)) {
		t.Error("Equal() = false for the same certificate parsed twice")
	}
	if c.Fingerprint() == [32]byte{} {
		t.Error("Fingerprint() is zero")
	}

	block, rest := pem.Decode(c.PEM())
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("PEM() is not a single CERTIFICATE block")
	}
	if !bytes.Equal(block.Bytes, x.Raw) {
		t.Error("PEM() does not round-trip the DER bytes")
	}
}
