// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package tlsnames_test

import (
	"crypto/tls"
	json "encoding/json/v2"
	"slices"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/tlsnames"
)

func TestPythonCipherNames(t *testing.T) {
	const script = `
import json
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.set_ciphers("ALL:eNULL:@SECLEVEL=0")
print(json.dumps({str(c["id"] & 65535): c["name"] for c in ctx.get_ciphers()}))
`
	var names map[uint16]string
	if err := json.Unmarshal(difftest.Python(t, script, nil), &names); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ suites []*tls.CipherSuite }{
		"current": {suites: tls.CipherSuites()},
		"legacy":  {suites: tls.InsecureCipherSuites()},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			checked := 0
			var unavailable []string
			for _, suite := range tt.suites {
				want, ok := names[suite.ID]
				if !ok {
					unavailable = append(unavailable, suite.Name)
					continue
				}
				got, ok := tlsnames.OpenSSL(suite.ID)
				if !ok || got != want {
					t.Errorf("OpenSSL(%#04x) = %q, %t; Python ssl wants %q", suite.ID, got, ok, want)
				}
				id, ok := tlsnames.SuiteID(want)
				if !ok || id != suite.ID {
					t.Errorf("SuiteID(%q) = %#04x, %t; Python ssl wants %#04x", want, id, ok, suite.ID)
				}
				checked++
			}
			if checked == 0 {
				t.Fatal("Python ssl exposed none of the Go suites")
			}
			slices.Sort(unavailable)
			t.Logf("Compared %d suites; Python ssl does not expose: %v", checked, unavailable)
		})
	}
}
