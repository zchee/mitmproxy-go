// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/net/idna"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
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

// crlPath is the path under which the certificate revocation list of the
// store's CA is served: "/mitmproxy-<serial>.crl", with the serial acting as
// a request-matching token (py:mitmproxy/addons/tlsconfig.py:582-583).
func (t *TLSConfig) crlPath() string {
	return fmt.Sprintf("/mitmproxy-%d.crl", t.store.DefaultCA().Serial())
}

// ipOrDNSName converts a host name or address into the GeneralName a
// certificate is requested for: an IP SAN when val parses as an address,
// a DNS SAN with the name IDNA-encoded otherwise
// (py:mitmproxy/addons/tlsconfig.py:647-654).
func ipOrDNSName(val string) (certs.GeneralName, error) {
	if addr, err := netip.ParseAddr(val); err == nil {
		return certs.IPAddress(addr), nil
	}
	name, err := encodeIDNA(val)
	if err != nil {
		return certs.GeneralName{}, fmt.Errorf("tlsconfig: subject alternative name %q: %w", val, err)
	}
	return certs.DNSName(name), nil
}

// getCert determines the common name, subject alternative names and
// organization the proxy's certificate should have for the connection, and
// fetches a matching entry from the store
// (py:mitmproxy/addons/tlsconfig.py:585-633).
func (t *TLSConfig) getCert(c *hookdata.Context) (*certs.Entry, error) {
	if t.store == nil {
		return nil, fmt.Errorf("tlsconfig: certificate store is not configured")
	}
	var altNames []certs.GeneralName
	var organization, crlDistributionPoint string

	// Use the upstream certificate when available.
	if t.options.Bool("upstream_cert") && len(c.Server.CertificateList) > 0 {
		upstreamCert, err := certs.ParseCert(c.Server.CertificateList[0])
		if err != nil {
			return nil, fmt.Errorf("tlsconfig: upstream certificate: %w", err)
		}
		if cn := upstreamCert.CN(); cn != "" {
			name, err := ipOrDNSName(cn)
			if err != nil {
				return nil, err
			}
			altNames = append(altNames, name)
		}
		altNames = append(altNames, upstreamCert.AltNames()...)
		organization = upstreamCert.Organization()

		// Replace the original URL path with the CA certificate's
		// serial number, which acts as a magic token the request hook
		// recognises.
		if crls := upstreamCert.CRLDistributionPoints(); len(crls) > 0 {
			u, err := url.Parse(crls[0])
			if err != nil {
				slog.Info(fmt.Sprintf("Failed to parse CRL URL: %q", crls[0]))
			} else {
				crlDistributionPoint = (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: t.crlPath()}).String()
			}
		}
	}

	// Add the SNI, or our local IP address without one.
	var subject string
	if c.Client.SNI != nil && *c.Client.SNI != "" {
		subject = *c.Client.SNI
	} else {
		subject = c.Client.Sockname.Host
	}
	name, err := ipOrDNSName(subject)
	if err != nil {
		return nil, err
	}
	altNames = append(altNames, name)

	// When a server address is already known, include it in the SANs too.
	if c.Server.Address != nil {
		name, err := ipOrDNSName(c.Server.Address.Host)
		if err != nil {
			return nil, err
		}
		altNames = append(altNames, name)
	}

	// Keep only the first occurrence of each name.
	seen := make(map[certs.GeneralName]struct{}, len(altNames))
	deduped := altNames[:0]
	for _, n := range altNames {
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		deduped = append(deduped, n)
	}

	// RFC 2818: when DNS SANs are present the common name is irrelevant;
	// mitmproxy still sets it to the first name.
	return t.store.GetCert(deduped[0].String(), deduped, organization, crlDistributionPoint)
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
