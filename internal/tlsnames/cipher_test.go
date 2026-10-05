// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsnames_test

import (
	"crypto/tls"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/tlsnames"
)

// Names are from OpenSSL's documented cipher-suite name table:
// https://docs.openssl.org/3.5/man1/openssl-ciphers/#cipher-suite-names.
func TestCipherNames(t *testing.T) {
	tests := map[string]struct {
		id   uint16
		iana string
	}{
		"RC4-SHA":                       {0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
		"DES-CBC3-SHA":                  {0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		"AES128-SHA":                    {0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		"AES256-SHA":                    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
		"AES128-SHA256":                 {0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
		"AES128-GCM-SHA256":             {0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
		"AES256-GCM-SHA384":             {0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
		"ECDHE-ECDSA-RC4-SHA":           {0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
		"ECDHE-ECDSA-AES128-SHA":        {0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
		"ECDHE-ECDSA-AES256-SHA":        {0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
		"ECDHE-RSA-RC4-SHA":             {0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
		"ECDHE-RSA-DES-CBC3-SHA":        {0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
		"ECDHE-RSA-AES128-SHA":          {0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
		"ECDHE-RSA-AES256-SHA":          {0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
		"ECDHE-ECDSA-AES128-SHA256":     {0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
		"ECDHE-RSA-AES128-SHA256":       {0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
		"ECDHE-ECDSA-AES128-GCM-SHA256": {0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		"ECDHE-ECDSA-AES256-GCM-SHA384": {0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		"ECDHE-RSA-AES128-GCM-SHA256":   {0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		"ECDHE-RSA-AES256-GCM-SHA384":   {0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		"ECDHE-RSA-CHACHA20-POLY1305":   {0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
		"ECDHE-ECDSA-CHACHA20-POLY1305": {0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
		"TLS_AES_128_GCM_SHA256":        {0x1301, "TLS_AES_128_GCM_SHA256"},
		"TLS_AES_256_GCM_SHA384":        {0x1302, "TLS_AES_256_GCM_SHA384"},
		"TLS_CHACHA20_POLY1305_SHA256":  {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := tlsnames.OpenSSL(tt.id)
			if !ok || got != name {
				t.Errorf("OpenSSL(%#04x) = %q, %t; want %q, true", tt.id, got, ok, name)
			}
			id, ok := tlsnames.SuiteID(name)
			if !ok || id != tt.id {
				t.Errorf("SuiteID(%q) = %#04x, %t; want %#04x, true", name, id, ok, tt.id)
			}
			if diff := gocmp.Diff(tt.iana, tlsnames.IANA(tt.id)); diff != "" {
				t.Errorf("IANA (-want +got):\n%s", diff)
			}
		})
	}
	for _, suite := range slices.Concat(tls.CipherSuites(), tls.InsecureCipherSuites()) {
		name, ok := tlsnames.OpenSSL(suite.ID)
		if !ok {
			t.Errorf("Go suite %s has no OpenSSL name", suite.Name)
		}
		if _, exists := tests[name]; !exists {
			t.Errorf("Go suite %s has no independent expected-name row", suite.Name)
		}
	}
}

func TestUnknownNames(t *testing.T) {
	tests := map[string]struct {
		name string
		id   uint16
	}{
		"empty":                        {name: "", id: 0},
		"unknown":                      {name: "not-a-cipher", id: 0xffff},
		"lowercase":                    {name: "aes128-sha", id: 0xfefe},
		"space":                        {name: "AES128-SHA ", id: 0x0a0a},
		"IANA spelling is not OpenSSL": {name: "TLS_RSA_WITH_AES_128_CBC_SHA", id: 0x7a7a},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got, ok := tlsnames.OpenSSL(tt.id); ok || got != "" {
				t.Errorf("OpenSSL(%#04x) = %q, %t; want empty, false", tt.id, got, ok)
			}
			if got, ok := tlsnames.SuiteID(tt.name); ok || got != 0 {
				t.Errorf("SuiteID(%q) = %#04x, %t; want zero, false", tt.name, got, ok)
			}
			if got, want := tlsnames.IANA(tt.id), tls.CipherSuiteName(tt.id); got != want {
				t.Errorf("IANA(%#04x) = %q, want %q", tt.id, got, want)
			}
		})
	}
}
