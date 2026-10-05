// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package certs

import (
	"crypto/x509"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestPKCS12Python(t *testing.T) {
	key, ca, err := CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	keyBundle, certBundle, err := encodePKCS12(key, ca, "mitmproxy")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile, certFile := filepath.Join(dir, "mitmproxy-ca.p12"), filepath.Join(dir, "mitmproxy-ca-cert.p12")
	if err := os.WriteFile(keyFile, keyBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, certBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(struct {
		KeyFile    string
		CertFile   string
		PrivateDER []byte
		CertDER    []byte
	}{keyFile, certFile, x509.MarshalPKCS1PrivateKey(key), ca.X509().Raw})
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

values = json.load(sys.stdin)
expected_key = serialization.load_der_private_key(base64.b64decode(values["PrivateDER"]), None)
expected_cert = base64.b64decode(values["CertDER"])
with_key = pkcs12.load_pkcs12(Path(values["KeyFile"]).read_bytes(), None)
cert_only = pkcs12.load_pkcs12(Path(values["CertFile"]).read_bytes(), None)
print(json.dumps({
    "fullPrivateKey": with_key.key.private_numbers() == expected_key.private_numbers(),
    "keyCertificate": with_key.cert.certificate.public_bytes(serialization.Encoding.DER) == expected_cert,
    "keyAdditionalEmpty": len(with_key.additional_certs) == 0,
    "certificateOnly": cert_only.key is None and cert_only.cert is None and len(cert_only.additional_certs) == 1 and cert_only.additional_certs[0].certificate.public_bytes(serialization.Encoding.DER) == expected_cert,
    "friendlyName": cert_only.additional_certs[0].friendly_name == b"mitmproxy",
}))
`, input)
	var got map[string]bool
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"fullPrivateKey": true, "keyCertificate": true, "keyAdditionalEmpty": true, "certificateOnly": true, "friendlyName": true}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("Python PKCS#12 recovery (-want +got):\n%s", diff)
	}
}

func TestDummyCertPython(t *testing.T) {
	key, ca, err := CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		commonName   string
		organization string
		crlURL       string
	}{
		"success: named leaf":        {commonName: "example.com", organization: "証明書", crlURL: "https://example.com/crl"},
		"success: empty subject":     {},
		"success: organization only": {organization: "Example"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			leaf, err := DummyCert(key, ca, tt.commonName, []GeneralName{DNSName("example.com"), EmailName("user@example.com"), URIName("https://example.com")}, tt.organization, tt.crlURL)
			if err != nil {
				t.Fatal(err)
			}
			input, err := json.Marshal(struct {
				PrivateDER   []byte
				CertDER      []byte
				CommonName   string
				Organization string
				CRLURL       string
			}{x509.MarshalPKCS1PrivateKey(key), ca.X509().Raw, tt.commonName, tt.organization, tt.crlURL})
			if err != nil {
				t.Fatal(err)
			}
			der := difftest.Python(t, `
import base64
import json
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from mitmproxy import certs

values = json.load(sys.stdin)
key = serialization.load_der_private_key(base64.b64decode(values["PrivateDER"]), None)
ca = x509.load_der_x509_certificate(base64.b64decode(values["CertDER"]))
leaf = certs.dummy_cert(key, ca, values["CommonName"] or None,
    [x509.DNSName("example.com"), x509.RFC822Name("user@example.com"), x509.UniformResourceIdentifier("https://example.com")],
    values["Organization"] or None, values["CRLURL"] or None)
sys.stdout.buffer.write(leaf.to_cryptography().public_bytes(serialization.Encoding.DER))
`, input)
			pythonLeaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(pythonLeaf.Extensions, leaf.X509().Extensions); diff != "" {
				t.Errorf("extensions (-Python +Go):\n%s", diff)
			}
			if diff := gocmp.Diff(pythonLeaf.RawSubject, leaf.X509().RawSubject); diff != "" {
				t.Errorf("subject (-Python +Go):\n%s", diff)
			}
			if err := pythonLeaf.CheckSignatureFrom(ca.X509()); err != nil {
				t.Errorf("Python leaf signed by Go CA: %v", err)
			}
		})
	}
}
