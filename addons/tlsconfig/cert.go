// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/net/idna"
)

// idnaProfile approximates the IDNA 2003 ToASCII operation that Python's
// "idna" codec performs when upstream encodes a SNI or certificate name
// (py:mitmproxy/addons/tlsconfig.py:647-654): UTS #46 transitional
// processing without the STD3 ASCII rules.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(false))

// encodeIDNA is Python's str.encode("idna") for a host name.
func encodeIDNA(name string) (string, error) {
	return idnaProfile.ToASCII(name)
}

// trustedRoots builds the certificate pool for upstream server verification
// from the ssl_verify_upstream_trusted_ca file and every PEM file in the
// ssl_verify_upstream_trusted_confdir directory. With neither option set it
// returns nil, so crypto/tls uses the system roots; upstream's OpenSSL
// context behaves the same with its default verify locations.
func trustedRoots(caFile, caDir *string) (*x509.CertPool, error) {
	if caFile == nil && caDir == nil {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if caFile != nil {
		path := expandUser(*caFile)
		pem, err := os.ReadFile(path) //nolint:gosec // The user explicitly selects the trusted CA file via the option.
		if err != nil {
			return nil, fmt.Errorf("tlsconfig: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tlsconfig: no trusted certificates in %s", path)
		}
	}
	if caDir != nil {
		// OpenSSL loads a hash-named directory lazily; here every
		// readable PEM file is loaded up front, and files that hold no
		// certificate are skipped (docs/compat.md).
		dir := expandUser(*caDir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("tlsconfig: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			pem, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // The user explicitly selects the trusted CA directory via the option.
			if err != nil {
				continue
			}
			pool.AppendCertsFromPEM(pem)
		}
	}
	return pool, nil
}
