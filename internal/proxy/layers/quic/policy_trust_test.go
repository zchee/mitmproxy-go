// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
)

func TestQUICPolicyTrustDirectory(t *testing.T) {
	certificate, rootPEM := originCertificate(t)
	tests := map[string]struct {
		required bool
		invalid  bool
	}{
		"directory ignores non-certificate files": {},
		"explicit CA file":                        {required: true},
		"explicit malformed CA file rejected":     {required: true, invalid: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "root.pem")
			data := rootPEM
			if tt.invalid {
				data = []byte("not a certificate")
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not PEM"), 0o600); err != nil {
				t.Fatal(err)
			}
			policy := tlsPolicy{verify: hookdata.VerifyRequired, serverName: "two-datagram.example"}
			if tt.required {
				policy.caFile = new(path)
			} else {
				policy.caPath = new(dir)
			}
			config, err := policy.config(false)
			if tt.invalid {
				if err == nil {
					t.Fatal("malformed explicit CA accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(certificate.Certificates[0].Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: config.RootCAs, DNSName: policy.serverName}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQUICPolicyHomeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ path, want string }{"home": {path: "~", want: home}, "home-relative": {path: "~/roots", want: home + "/roots"}, "relative": {path: "roots", want: "roots"}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := expandTrustPath(tt.path); got != tt.want {
				t.Fatalf("expanded path=%q,want=%q", got, tt.want)
			}
		})
	}
}
