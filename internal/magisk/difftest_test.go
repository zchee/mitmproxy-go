// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package magisk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // Predicts subject_hash_old, which is MD5 by definition.
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	json "encoding/json/v2"
	"fmt"
	"math/big"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

// subjectHashOldPython asks the pinned Python for the subject_hash_old of the
// DER certificate, computed as mitmproxy/utils/magisk.py computes it.
func subjectHashOldPython(t *testing.T, certDER []byte) string {
	t.Helper()
	input, err := json.Marshal(struct{ CertDER []byte }{certDER})
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import hashlib
import json
import sys

from cryptography import x509

values = json.load(sys.stdin)
cert = x509.load_der_x509_certificate(base64.b64decode(values["CertDER"]))
full_hash = hashlib.md5(cert.subject.public_bytes()).digest()
sho = full_hash[0] | (full_hash[1] << 8) | (full_hash[2] << 16) | full_hash[3] << 24
print(json.dumps({"hash": hex(sho)[2:]}))
`, input)
	var result struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode %q: %v", output, err)
	}
	return result.Hash
}

// leadingZeroCert builds a self-signed certificate whose subject hash begins
// with a zero nibble, so the hexadecimal form is shorter than eight digits and
// the no-leading-zeros formatting is exercised.
func leadingZeroCert(t *testing.T) *x509.Certificate {
	t.Helper()
	cn := ""
	for i := range 1 << 20 {
		cn = fmt.Sprintf("leading-zero-%d", i)
		der, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		digest := md5.Sum(der) //nolint:gosec // Predicts subject_hash_old, which is MD5 by definition.
		value := uint32(digest[0]) | uint32(digest[1])<<8 | uint32(digest[2])<<16 | uint32(digest[3])<<24
		if value < 0x10000000 {
			break
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if got := SubjectHashOld(cert); len(got) >= 8 {
		t.Fatalf("SubjectHashOld = %q, want a hash shorter than eight digits", got)
	}
	return cert
}

func TestSubjectHashOldPython(t *testing.T) {
	tests := map[string]struct {
		ca func(t *testing.T) *x509.Certificate
	}{
		"success: fixture CA":               {ca: fixtureCA},
		"success: hash with a leading zero": {ca: leadingZeroCert},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ca := tt.ca(t)
			if diff := gocmp.Diff(subjectHashOldPython(t, ca.Raw), SubjectHashOld(ca)); diff != "" {
				t.Errorf("subject_hash_old (-python +go):\n%s", diff)
			}
		})
	}
}
