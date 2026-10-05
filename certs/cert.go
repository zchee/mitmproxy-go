// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/dsa" //nolint:staticcheck // SA1019: upstream reports DSA key info for legacy certificates.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
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

// subjectAttr returns the value of the first subject attribute with the
// given type, reading the raw subject so the original order decides
// which attribute is first.
func (c *Cert) subjectAttr(oid asn1.ObjectIdentifier) (string, bool) {
	attrs, err := parseName(c.x.RawSubject)
	if err != nil {
		return "", false
	}
	for _, a := range attrs {
		if a.oid.Equal(oid) {
			return a.val, true
		}
	}
	return "", false
}

// CN returns the common name of the subject, or "" when the subject has
// none (mitmproxy's None).
func (c *Cert) CN() string {
	cn, _ := c.subjectAttr(oidCommonName)
	return cn
}

// Organization returns the organization name of the subject, or "" when
// the subject has none.
func (c *Cert) Organization() string {
	org, _ := c.subjectAttr(oidOrganization)
	return org
}

// Subject returns the subject's attributes in certificate order,
// multi-valued RDNs flattened in place.
func (c *Cert) Subject() []KeyVal {
	attrs, err := parseName(c.x.RawSubject)
	if err != nil {
		return nil
	}
	return keyVals(attrs)
}

// Issuer returns the issuer's attributes in certificate order.
func (c *Cert) Issuer() []KeyVal {
	attrs, err := parseName(c.x.RawIssuer)
	if err != nil {
		return nil
	}
	return keyVals(attrs)
}

// AltNames returns the entries of the SubjectAlternativeName extension
// in certificate order. A certificate without the extension, or with one
// that does not parse, has no alt names; an entry of an unmodelled type
// is kept raw as a [GeneralNameOther].
func (c *Cert) AltNames() []GeneralName {
	for _, ext := range c.x.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			names, err := parseGeneralNames(ext.Value)
			if err != nil {
				return []GeneralName{}
			}
			return names
		}
	}
	return []GeneralName{}
}

// CRLDistributionPoints returns the URI of every distribution point
// whose first name is a URI, in certificate order.
func (c *Cert) CRLDistributionPoints() []string {
	for _, ext := range c.x.Extensions {
		if ext.Id.Equal(oidCRLDistributionPoints) {
			urls, err := parseCRLDistributionPoints(ext.Value)
			if err != nil {
				return []string{}
			}
			return urls
		}
	}
	return []string{}
}

// KeyInfo returns the public key's algorithm name and size in bits, as
// mitmproxy's keyinfo reports them: "RSA", "DSA" or "EC (<curve>)" with
// cryptography's curve names, and otherwise the key type's name with
// size -1 when it has no size.
func (c *Cert) KeyInfo() (string, int) {
	switch pub := c.x.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *dsa.PublicKey:
		return "DSA", pub.P.BitLen()
	case *ecdsa.PublicKey:
		name := pub.Curve.Params().Name
		if sec, ok := secCurveNames[name]; ok {
			name = sec
		}
		return fmt.Sprintf("EC (%s)", name), pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", -1
	default:
		return fmt.Sprintf("%T", pub), -1
	}
}

// secCurveNames maps Go's NIST curve names to the SEC 2 names
// cryptography uses in curve.name.
var secCurveNames = map[string]string{
	"P-224": "secp224r1",
	"P-256": "secp256r1",
	"P-384": "secp384r1",
	"P-521": "secp521r1",
}

// String returns mitmproxy's repr of the certificate, for example
// "<Cert(cn='example.com', altnames=['a.example.com'])>"; a missing
// common name renders as None.
func (c *Cert) String() string {
	var b []byte
	b = append(b, "<Cert(cn="...)
	if cn, ok := c.subjectAttr(oidCommonName); ok {
		b = pyrepr.AppendStr(b, cn)
	} else {
		b = append(b, "None"...)
	}
	b = append(b, ", altnames=["...)
	for i, n := range c.AltNames() {
		if i > 0 {
			b = append(b, ", "...)
		}
		b = pyrepr.AppendStr(b, n.String())
	}
	b = append(b, "])>"...)
	return string(b)
}
