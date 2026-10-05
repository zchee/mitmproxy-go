// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package certs generates and stores the TLS certificates of the proxy.
//
// It is the port of mitmproxy's certs.py: [CreateCA] makes the long-lived
// root certificate, [DummyCert] issues the short-lived leaf certificates
// the proxy presents for intercepted hosts, and [Store] caches the issued
// leaves and the certificates the user configured. [FromStore] loads a
// configuration directory in mitmproxy's `~/.mitmproxy` layout, creating
// it with the same file set and file modes when it does not exist yet.
//
// The store synchronises itself with its own mutex, because it is read
// outside the hook dispatch domain: the onboarding handlers and the DTLS
// certificate callback reach it from their own goroutines.
package certs

import (
	"errors"
	"time"
)

// Validity periods of the generated certificates. The periods are offset
// by [ValidityOffset], i.e. every certificate is backdated a bit to
// account for clients with incorrect clocks. The CA default is
// deliberately not longer: see https://github.com/mitmproxy/mitmproxy/issues/815.
const (
	// CAExpiry is the validity period of a [CreateCA] certificate.
	CAExpiry = 10 * 365 * 24 * time.Hour
	// CertExpiry is the validity period of a [DummyCert] leaf.
	CertExpiry = 199 * 24 * time.Hour
	// CRLExpiry is how long past its creation the in-memory CRL stays valid.
	CRLExpiry = 7 * 24 * time.Hour
	// ValidityOffset is added to the current time to get a certificate's
	// start of validity, backdating it by two days.
	ValidityOffset = -2 * 24 * time.Hour
)

// ErrPassphraseRequired is returned when a PEM private key is encrypted
// and no passphrase was given.
var ErrPassphraseRequired = errors.New("certs: private key is encrypted, but no passphrase was given")

// DefaultDHParam is the Diffie-Hellman parameter file content written to
// `<basename>-dhparam.pem`, byte for byte as mitmproxy writes it, with
// the leading newline. mitmproxy generated it once with "openssl dhparam"
// because generating it on startup is too slow; the Go port writes the
// file only for layout compatibility and never uses it, because
// crypto/tls has no finite-field DHE cipher suites.
const DefaultDHParam = `
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAyT6LzpwVFS3gryIo29J5icvgxCnCebcdSe/NHMkD8dKJf8suFCg3
O2+dguLakSVif/t6dhImxInJk230HmfC8q93hdcg/j8rLGJYDKu3ik6H//BAHKIv
j5O9yjU3rXCfmVJQic2Nne39sg3CreAepEts2TvYHhVv3TEAzEqCtOuTjgDv0ntJ
Gwpj+BJBRQGG9NvprX1YGJ7WOFBP/hWU7d6tgvE6Xa7T/u9QIKpYHMIkcN/l3ZFB
chZEqVlyrcngtSXCROTPcDOQ6Q8QzhaBJS+Z6rcsd7X+haiQqvoFcmaJ08Ks6LQC
ZIL2EtYJw8V8z7C0igVEBIADZBI6OTbuuhDwRw//zU1uq52Oc48CIZlGxTYG/Evq
o9EWAXUYVzWkDSTeBH1r4z/qLPE2cnhtMxbFxuvK53jGB0emy2y1Ei6IhKshJ5qX
IB/aE7SSHyQ3MDHHkCmQJCsOd4Mo26YX61NZ+n501XjqpCBQ2+DfZCBh8Va2wDyv
A2Ryg9SUz8j0AXViRNMJgJrr446yro/FuJZwnQcO3WQnXeqSBnURqKjmqkeFP+d8
6mk2tqJaY507lRNqtGlLnj7f5RNoBFJDCLBNurVgfvq9TCVWKDIFD4vZRjCrnl6I
rD693XKIHUCWOjMh1if6omGXKHH40QuME2gNa50+YPn1iYDl88uDbbMCAQI=
-----END DH PARAMETERS-----
`
