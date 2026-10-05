// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package tlsnames translates the cipher suite names used by crypto/tls and
// OpenSSL. It names all suites implemented by crypto/tls, including insecure
// suites; naming a suite does not enable it or imply that it should be used.
package tlsnames

import "crypto/tls"

var opensslNames = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                      "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "DES-CBC3-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:                  "AES128-SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:                  "AES256-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               "AES128-SHA256",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               "AES128-GCM-SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               "AES256-GCM-SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "ECDHE-ECDSA-RC4-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "ECDHE-ECDSA-AES128-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "ECDHE-ECDSA-AES256-SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "ECDHE-RSA-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "ECDHE-RSA-DES-CBC3-SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "ECDHE-RSA-AES128-SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "ECDHE-RSA-AES256-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "ECDHE-ECDSA-AES128-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "ECDHE-RSA-AES128-SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "ECDHE-ECDSA-AES128-GCM-SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "ECDHE-ECDSA-AES256-GCM-SHA384",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "ECDHE-RSA-AES128-GCM-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "ECDHE-RSA-AES256-GCM-SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "ECDHE-RSA-CHACHA20-POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "ECDHE-ECDSA-CHACHA20-POLY1305",
	tls.TLS_AES_128_GCM_SHA256:                        "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                        "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:                  "TLS_CHACHA20_POLY1305_SHA256",
}

var suiteIDs = func() map[string]uint16 {
	ids := make(map[string]uint16, len(opensslNames))
	for id, name := range opensslNames {
		ids[name] = id
	}
	return ids
}()

// OpenSSL returns the OpenSSL name of a cipher suite implemented by crypto/tls.
// An unknown ID returns an empty string and false.
func OpenSSL(id uint16) (string, bool) {
	name, ok := opensslNames[id]
	return name, ok
}

// SuiteID returns the crypto/tls suite ID for an exact, case-sensitive OpenSSL
// name. It does not parse cipher expressions or aliases. An unknown name returns
// zero and false.
func SuiteID(openssl string) (uint16, bool) {
	id, ok := suiteIDs[openssl]
	return id, ok
}

// IANA returns the standard IANA cipher suite name, or a hexadecimal ID for an
// unknown suite, as crypto/tls.CipherSuiteName does.
func IANA(id uint16) string { return tls.CipherSuiteName(id) }
