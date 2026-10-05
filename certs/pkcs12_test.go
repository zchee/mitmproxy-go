// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"bytes"
	"crypto/rsa"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestEncodePKCS12(t *testing.T) {
	key, ca, err := CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	keyBundle, certBundle, err := encodePKCS12(key, ca, "mitmproxy")
	if err != nil {
		t.Fatal(err)
	}
	decodedKey, decodedCert, err := pkcs12.Decode(keyBundle, "")
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, ok := decodedKey.(*rsa.PrivateKey)
	if !ok || !key.Equal(rsaKey) {
		t.Error("key-bearing bundle did not preserve the complete private key")
	}
	if !bytes.Equal(decodedCert.Raw, ca.X509().Raw) {
		t.Error("key-bearing bundle did not preserve the certificate")
	}
	certificates, err := pkcs12.DecodeTrustStore(certBundle, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 || !bytes.Equal(certificates[0].Raw, ca.X509().Raw) {
		t.Error("certificate-only bundle did not preserve exactly one certificate")
	}
}
