// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestDistrustedCATable(t *testing.T) {
	makeCA := func(serial int64) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "owned synthetic CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	first, second := makeCA(1), makeCA(2)
	tests := map[string]struct{ run func(*testing.T) }{
		"source_inventory": {func(t *testing.T) {
			// Independent literals from Mozilla's incident comments 0 and 2 and
			// root inclusion record 1515465, retrieved 2026-10-27.
			want := []string{
				"E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838",
				"98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B",
				"42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493",
				"432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3",
				"CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F",
				"0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19",
				"579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512",
				"5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699",
				"45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE",
				"FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F",
				"7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489",
				"62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72",
				"86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B",
			}
			if diff := gocmp.Diff(want, strings.Fields(distrustedTLSCAFingerprints)); diff != "" {
				t.Fatalf("incident inventory (-want +got):\n%s", diff)
			}
		}},
		"unique_identities": {func(t *testing.T) {
			table := DistrustedTLSCAs()
			if got := len(table.fingerprints); got != 13 {
				t.Fatalf("unique certificate identities = %d, want 13", got)
			}
		}},
		"synthetic_match": {func(t *testing.T) {
			table, err := ParseCADistrust(fmt.Sprintf("%X", sha256.Sum256(first.Raw)))
			if err != nil {
				t.Fatal(err)
			}
			if err := table.CheckChain([]*x509.Certificate{first}); err == nil || !strings.Contains(err.Error(), "explicitly distrusted") {
				t.Fatalf("matching owned CA was not explicitly rejected: %v", err)
			}
		}},
		"synthetic_nonmatch": {func(t *testing.T) {
			if err := DistrustedTLSCAs().CheckChain([]*x509.Certificate{first}); err != nil {
				t.Fatalf("owned unrelated CA: %v", err)
			}
		}},
		"matching_name_different_identity": {func(t *testing.T) {
			if diff := gocmp.Diff(first.Subject, second.Subject); diff != "" {
				t.Fatal(diff)
			}
			table, err := ParseCADistrust(fmt.Sprintf("%X", sha256.Sum256(first.Raw)))
			if err != nil {
				t.Fatal(err)
			}
			if err := table.CheckChain([]*x509.Certificate{second}); err != nil {
				t.Fatalf("name-only match incorrectly rejected unrelated CA: %v", err)
			}
		}},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}

func TestDistrustedCATableParser(t *testing.T) {
	valid := strings.Repeat("ab", sha256.Size)
	tests := map[string]struct {
		input     string
		wantError bool
	}{
		"valid":               {input: "\n\t" + valid + " \n"},
		"empty":               {input: " \n\t", wantError: true},
		"malformed_hex":       {input: strings.Repeat("gg", sha256.Size), wantError: true},
		"wrong_digest_length": {input: "abcd", wantError: true},
		"duplicate_identity":  {input: valid + "\n" + strings.ToUpper(valid), wantError: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			table, err := ParseCADistrust(test.input)
			if (err != nil) != test.wantError {
				t.Fatalf("ParseCADistrust(%q) error = %v, wantError %t", test.input, err, test.wantError)
			}
			if err == nil && len(table.fingerprints) != 1 {
				t.Fatalf("parsed %d identities, want one", len(table.fingerprints))
			}
		})
	}
}
