// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"crypto/tls"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/tlsnames"
	"github.com/zchee/mitmproxy-go/options"
)

// tlsVersionNames are the values of the tls_version_* options, in upstream's
// enum order (py:mitmproxy/net/tls.py Version).
var tlsVersionNames = []string{"UNBOUNDED", "SSL3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}

// insecureTLSMinVersions are the tls_version_*_min values upstream documents
// as insecure (py:mitmproxy/net/tls.py INSECURE_TLS_MIN_VERSIONS).
var insecureTLSMinVersions = []string{"UNBOUNDED", "SSL3", "TLS1", "TLS1_1"}

// supportedTLSVersionNames are the real TLS versions crypto/tls can negotiate.
// SSL3 is the one option value outside it: Go dropped SSLv3 entirely, where
// upstream's libssl build decides (docs/compat.md).
var supportedTLSVersionNames = []string{"TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}

// tlsVersionIDs maps the real TLS versions onto crypto/tls version numbers.
var tlsVersionIDs = map[string]uint16{
	"TLS1":   tls.VersionTLS10,
	"TLS1_1": tls.VersionTLS11,
	"TLS1_2": tls.VersionTLS12,
	"TLS1_3": tls.VersionTLS13,
}

// minTLSVersion maps a tls_version_*_min option value onto the MinVersion of
// a tls.Config. UNBOUNDED and the unsupported SSL3 both become TLS 1.0, the
// lowest version crypto/tls can speak (docs/compat.md).
func minTLSVersion(name string) uint16 {
	if v, ok := tlsVersionIDs[name]; ok {
		return v
	}
	return tls.VersionTLS10
}

// maxTLSVersion maps a tls_version_*_max option value onto the MaxVersion of
// a tls.Config. UNBOUNDED becomes TLS 1.3, the highest version crypto/tls can
// speak; the unsupported SSL3 becomes TLS 1.0 (docs/compat.md).
func maxTLSVersion(name string) uint16 {
	if v, ok := tlsVersionIDs[name]; ok {
		return v
	}
	if name == "SSL3" {
		return tls.VersionTLS10
	}
	return tls.VersionTLS13
}

// ecCurves maps the tls_ecdh_curve_* option values onto crypto/tls curves.
// The names are the elliptic-curve names upstream accepts (the cryptography
// package's curve names, py:mitmproxy/net/tls.py EC_CURVES) restricted to the
// curves crypto/tls implements; every other name fails configure with an
// OptionsError, as an unknown name does upstream (docs/compat.md).
var ecCurves = map[string]tls.CurveID{
	"secp256r1": tls.CurveP256,
	"secp384r1": tls.CurveP384,
	"secp521r1": tls.CurveP521,
}

// ecCurveNames lists the valid tls_ecdh_curve_* values for error messages,
// in display order.
var ecCurveNames = []string{"secp256r1", "secp384r1", "secp521r1"}

// curvePreferences returns the CurvePreferences for a tls_ecdh_curve_* option
// value, or nil (the crypto/tls defaults) when the option is unset.
func curvePreferences(name *string) []tls.CurveID {
	if name == nil {
		return nil
	}
	if curve, ok := ecCurves[*name]; ok {
		return []tls.CurveID{curve}
	}
	return nil
}

// suiteIDs maps a connection's cipher list onto crypto/tls cipher suite ids.
// Every entry must be the exact OpenSSL name of a suite crypto/tls implements;
// an alias, an exclusion, a sort keyword or an unknown or unsupported name is
// an error naming the entry, because crypto/tls has no cipher-string engine
// to hand it to (docs/compat.md). option names the option or connection field
// the list came from.
func suiteIDs(option string, ciphers []string) ([]uint16, error) {
	ids := make([]uint16, 0, len(ciphers))
	for _, name := range ciphers {
		id, ok := tlsnames.SuiteID(name)
		if !ok {
			return nil, options.Errorf("%s: %q is not the exact OpenSSL name of a cipher suite supported by crypto/tls", option, name)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// parseCipherOption validates a ciphers_client/ciphers_server option value:
// colon-separated exact OpenSSL suite names.
func parseCipherOption(option, value string) ([]uint16, error) {
	return suiteIDs(option, strings.Split(value, ":"))
}
