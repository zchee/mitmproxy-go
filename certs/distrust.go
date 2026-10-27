// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// CADistrust is an immutable set of explicitly distrusted certificate identities.
// Its zero value distrusts no certificates; copying a value shares read-only data.
type CADistrust struct {
	fingerprints map[[sha256.Size]byte]struct{}
}

// ParseCADistrust parses whitespace-separated full-certificate SHA-256 hex digests.
// It rejects empty tables, invalid digests and duplicate certificate identities.
func ParseCADistrust(data string) (CADistrust, error) {
	out := CADistrust{fingerprints: make(map[[sha256.Size]byte]struct{})}
	for digest := range strings.FieldsSeq(data) {
		if len(digest) != sha256.Size*2 {
			return CADistrust{}, fmt.Errorf("certs: CA fingerprint must contain 64 hex digits")
		}
		var fingerprint [sha256.Size]byte
		if _, err := hex.Decode(fingerprint[:], []byte(digest)); err != nil {
			return CADistrust{}, fmt.Errorf("certs: invalid CA fingerprint: %w", err)
		}
		if _, exists := out.fingerprints[fingerprint]; exists {
			return CADistrust{}, fmt.Errorf("certs: duplicate CA fingerprint %X", fingerprint)
		}
		out.fingerprints[fingerprint] = struct{}{}
	}
	if len(out.fingerprints) == 0 {
		return CADistrust{}, fmt.Errorf("certs: empty CA distrust table")
	}
	return out, nil
}

// DistrustedTLSCAs returns the incident identities in the embedded distrust table.
// It panics only if the application's embedded fingerprint data is malformed.
func DistrustedTLSCAs() CADistrust {
	table, err := ParseCADistrust(distrustedTLSCAFingerprints)
	if err != nil {
		panic(fmt.Sprintf("certs: invalid embedded TLS CA distrust table: %v", err))
	}
	return table
}

// VerifyConnection supplements normal TLS verification with explicit distrust.
// It checks both wire certificates and verified paths, including unsent roots,
// and also runs on resumed TLS sessions. It must not be installed for insecure
// connections, where the operator has explicitly disabled verification.
func (d CADistrust) VerifyConnection(state tls.ConnectionState) error {
	if err := d.CheckChain(state.PeerCertificates); err != nil {
		return err
	}
	for _, chain := range state.VerifiedChains {
		if err := d.CheckChain(chain); err != nil {
			return err
		}
	}
	return nil
}

// VerifyPeerCertificate supplements DTLS verification with explicit distrust.
// The DTLS stack supplies verified paths on full handshakes and before offering
// session resumption, so unsent trust anchors are checked in both cases.
func (d CADistrust) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	state := tls.ConnectionState{VerifiedChains: verifiedChains}
	for _, raw := range rawCerts {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("certs: parse DTLS peer certificate: %w", err)
		}
		state.PeerCertificates = append(state.PeerCertificates, certificate)
	}
	return d.VerifyConnection(state)
}

// CheckChain rejects any explicitly distrusted certificate in chain.
// Callers check both peer-supplied certificates and verified chains, since trust
// anchors need not appear on the wire. It does not replace normal verification.
func (d CADistrust) CheckChain(chain []*x509.Certificate) error {
	for _, certificate := range chain {
		if certificate == nil {
			return fmt.Errorf("certs: nil certificate in TLS chain")
		}
		fingerprint := sha256.Sum256(certificate.Raw)
		if _, blocked := d.fingerprints[fingerprint]; blocked {
			return fmt.Errorf("certs: explicitly distrusted TLS CA certificate (SHA-256 %X)", fingerprint)
		}
	}
	return nil
}
