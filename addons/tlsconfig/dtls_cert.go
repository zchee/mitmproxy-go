// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"slices"

	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/certs"
)

// dtlsCertificateCallback retains only immutable certificate inputs and the
// synchronized store, never the hook context or options. Pion calls it outside
// dispatch, including on no-SNI handshakes because Certificates stays empty.
func dtlsCertificateCallback(store *certs.Store, entry *certs.Entry, upstream [][]byte) (func(*dtls.ClientHelloInfo) (*tls.Certificate, error), error) {
	names := entry.Cert.AltNames()
	commonName := entry.Cert.CN()
	organization := entry.Cert.Organization()
	crlURL := ""
	if points := entry.Cert.CRLDistributionPoints(); len(points) > 0 {
		crlURL = points[0]
	}
	var extras [][]byte
	for _, raw := range upstream {
		certificate, err := certs.ParseCert(raw)
		if err != nil {
			return nil, fmt.Errorf("tlsconfig: upstream certificate: %w", err)
		}
		extras = append(extras, bytes.Clone(certificate.X509().Raw))
	}
	return func(hello *dtls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil {
			return nil, fmt.Errorf("tlsconfig: missing DTLS ClientHello information")
		}
		sans := names
		if hello.ServerName != "" {
			name, err := ipOrDNSName(hello.ServerName)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(sans, name) {
				sans = append(slices.Clone(sans), name)
			}
		}
		selected, err := store.GetCert(commonName, sans, organization, crlURL)
		if err != nil {
			return nil, err
		}
		certificate := &tls.Certificate{
			Certificate: [][]byte{bytes.Clone(selected.Cert.X509().Raw)},
			PrivateKey:  selected.PrivateKey,
			Leaf:        selected.Cert.X509(),
		}
		if len(selected.ChainCerts) > 1 {
			for _, chain := range selected.ChainCerts[1:] {
				certificate.Certificate = append(certificate.Certificate, bytes.Clone(chain.X509().Raw))
			}
		}
		for _, extra := range extras {
			certificate.Certificate = append(certificate.Certificate, bytes.Clone(extra))
		}
		return certificate, nil
	}, nil
}
