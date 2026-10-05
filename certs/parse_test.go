// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/x509"
	"encoding/asn1"
	"net/netip"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestParseNameMultivaluedRDN(t *testing.T) {
	// These attributes and their order are from upstream's
	// test_multi_valued_rdns. Raw SET bytes preserve the provided order.
	want := []KeyVal{{"2.5.4.12", "Test"}, {"CN", "Multivalue"}, {"2.5.4.4", "RDNs"}, {"O", "TSLA"}, {"O", "PyCA"}}
	attrs := []struct {
		OID   asn1.ObjectIdentifier
		Value string `asn1:"utf8"`
	}{
		{asn1.ObjectIdentifier{2, 5, 4, 12}, "Test"},
		{oidCommonName, "Multivalue"},
		{asn1.ObjectIdentifier{2, 5, 4, 4}, "RDNs"},
		{oidOrganization, "TSLA"},
		{oidOrganization, "PyCA"},
	}
	var sets, inner []byte
	for i, attr := range attrs {
		b, err := asn1.Marshal(attr)
		if err != nil {
			t.Fatal(err)
		}
		inner = append(inner, b...)
		if i == 3 || i == 4 {
			set, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: inner})
			if err != nil {
				t.Fatal(err)
			}
			sets = append(sets, set...)
			inner = nil
		}
	}
	raw, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: sets})
	if err != nil {
		t.Fatal(err)
	}
	cert := NewCert(&x509.Certificate{RawSubject: raw, RawIssuer: raw})
	if diff := gocmp.Diff(want, cert.Subject()); diff != "" {
		t.Errorf("Subject() (-want +got):\n%s", diff)
	}
	if diff := gocmp.Diff(want, cert.Issuer()); diff != "" {
		t.Errorf("Issuer() (-want +got):\n%s", diff)
	}
	if cert.Organization() != "TSLA" {
		t.Errorf("first O = %q, want TSLA", cert.Organization())
	}
}

func TestDecodeNameString(t *testing.T) {
	tests := map[string]struct {
		tag  int
		data []byte
		want string
	}{
		"UTF8String":      {asn1.TagUTF8String, []byte("bücher"), "bücher"},
		"PrintableString": {asn1.TagPrintableString, []byte("Example"), "Example"},
		"BMPString":       {30, []byte{0, 'A', 0, 0xfc}, "Aü"},
		"UniversalString": {28, []byte{0, 0, 0, 'A', 0, 1, 0xf6, 0}, "A😀"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := decodeNameString(asn1.RawValue{Tag: tt.tag, Bytes: tt.data}); got != tt.want {
				t.Errorf("decodeNameString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseGeneralNames(t *testing.T) {
	tests := map[string]struct {
		der     []byte
		want    []GeneralName
		wantErr bool
	}{
		"empty": {der: []byte{0x30, 0}, want: []GeneralName{}},
		"mixed names preserve order": {
			der:  []byte{0x30, 20, 0x87, 4, 127, 0, 0, 1, 0x86, 1, 'u', 0x81, 3, 'a', '@', 'b', 0x82, 4, 't', 'e', 's', 't'},
			want: []GeneralName{IPAddress(netip.MustParseAddr("127.0.0.1")), URIName("u"), EmailName("a@b"), DNSName("test")},
		},
		"unknown entry preserves DER": {der: []byte{0x30, 3, 0x88, 1, 42}, want: []GeneralName{otherName([]byte{0x88, 1, 42})}},
		"invalid IP preserves DER":    {der: []byte{0x30, 3, 0x87, 1, 42}, want: []GeneralName{otherName([]byte{0x87, 1, 42})}},
		"error: truncated":            {der: []byte{0x30, 2, 0x82}, wantErr: true},
		"error: wrong outer tag":      {der: []byte{0x31, 0}, wantErr: true},
		"error: trailing bytes":       {der: []byte{0x30, 0, 0}, wantErr: true},
		"error: truncated name":       {der: []byte{0x30, 2, 0x82, 3}, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseGeneralNames(tt.der)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseGeneralNames() error = %v, wantErr %t", err, tt.wantErr)
			}
			if diff := gocmp.Diff(tt.want, got, gocmp.Comparer(func(a, b GeneralName) bool { return a == b })); diff != "" {
				t.Errorf("parseGeneralNames() (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseNameRejectsMalformedDER(t *testing.T) {
	tests := map[string]struct{ data []byte }{
		"empty input":         {},
		"truncated sequence":  {[]byte{0x30, 10, 0x31}},
		"wrong outer tag":     {[]byte{0x31, 0}},
		"trailing bytes":      {[]byte{0x30, 0, 0}},
		"truncated RDN":       {[]byte{0x30, 2, 0x31, 5}},
		"truncated attribute": {[]byte{0x30, 4, 0x31, 2, 0x30, 5}},
		"invalid OID":         {[]byte{0x30, 6, 0x31, 4, 0x30, 2, 0x06, 1}},
		"missing value":       {[]byte{0x30, 7, 0x31, 5, 0x30, 3, 0x06, 1, 42}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseName(tt.data); err == nil {
				t.Errorf("parseName(%x) succeeded", tt.data)
			}
		})
	}
}
