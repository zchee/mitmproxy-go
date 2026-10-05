// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"
)

// KeyVal is one attribute of a distinguished name, as mitmproxy reports
// subjects and issuers: the RFC 4514 short name when the attribute has
// one ("CN", "O"), otherwise the dotted OID, paired with the value.
type KeyVal struct {
	Key   string
	Value string
}

// Cert is a (TLS) certificate. It wraps the parsed [x509.Certificate]
// and reads names and extensions from the raw DER where Go's parser
// would reorder or drop them, so what it reports matches what mitmproxy
// reports for the same certificate.
type Cert struct {
	x *x509.Certificate
}

// NewCert returns the Cert for an already parsed certificate.
func NewCert(cert *x509.Certificate) *Cert {
	return &Cert{x: cert}
}

// X509 returns the underlying certificate. The caller must not modify
// it.
func (c *Cert) X509() *x509.Certificate {
	return c.x
}

// PEM returns the certificate serialised as a PEM CERTIFICATE block.
func (c *Cert) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.x.Raw})
}

// Fingerprint returns the SHA-256 digest of the DER-encoded certificate.
func (c *Cert) Fingerprint() [sha256.Size]byte {
	return sha256.Sum256(c.x.Raw)
}

// Equal reports whether the two certificates have the same fingerprint,
// as mitmproxy's Cert equality does.
func (c *Cert) Equal(other *Cert) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.Fingerprint() == other.Fingerprint()
}

// Serial returns the certificate's serial number.
func (c *Cert) Serial() *big.Int {
	return c.x.SerialNumber
}

// NotBefore returns the start of the validity period in UTC.
func (c *Cert) NotBefore() time.Time {
	return c.x.NotBefore.UTC()
}

// NotAfter returns the end of the validity period in UTC.
func (c *Cert) NotAfter() time.Time {
	return c.x.NotAfter.UTC()
}

// HasExpired reports whether the validity period has ended.
func (c *Cert) HasExpired() bool {
	return time.Now().UTC().After(c.NotAfter())
}

// IsCA reports whether the certificate carries a BasicConstraints
// extension with the CA flag set; a certificate without the extension is
// not a CA, as mitmproxy reports it.
func (c *Cert) IsCA() bool {
	return c.x.BasicConstraintsValid && c.x.IsCA
}
