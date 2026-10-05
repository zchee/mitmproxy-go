// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// DummyCert issues a leaf using ca's public key and the supplied signing key.
// SAN order is preserved; commonName is omitted when empty or at least 64
// characters long. Empty organization and crlURL omit those optional fields.
// It returns an error for an invalid name, unsupported key, or signing failure.
func DummyCert(privateKey crypto.Signer, ca *Cert, commonName string, sans []GeneralName, organization, crlURL string) (*Cert, error) {
	if ca == nil || ca.X509() == nil {
		return nil, errors.New("certs: missing CA certificate")
	}
	algorithm, err := sha256SignatureAlgorithm(privateKey)
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().UTC().Add(ValidityOffset)
	validCN := commonName != "" && utf8.RuneCountInString(commonName) < 64
	var attrs []nameAttr
	if validCN {
		attrs = append(attrs, nameAttr{oid: oidCommonName, val: commonName})
	}
	if organization != "" {
		attrs = append(attrs, nameAttr{oid: oidOrganization, val: organization})
	}
	subject, err := marshalSubject(attrs)
	if err != nil {
		return nil, err
	}
	sanDER, err := marshalGeneralNames(sans)
	if err != nil {
		return nil, err
	}
	issuer := ca.X509()
	keyID := issuer.SubjectKeyId
	if len(keyID) == 0 {
		keyID, err = publicKeyID(issuer.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	akiDER, err := asn1.Marshal(struct {
		KeyIdentifier []byte `asn1:"tag:0"`
	}{keyID})
	if err != nil {
		return nil, fmt.Errorf("certs: encode authority key identifier: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:       newSerial(),
		RawSubject:         subject,
		NotBefore:          notBefore,
		NotAfter:           notBefore.Add(CertExpiry),
		SignatureAlgorithm: algorithm,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 10, 6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 1}},
			{Id: oidSubjectAltName, Critical: !validCN, Value: sanDER},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: akiDER},
		},
	}
	if crlURL != "" {
		uri, err := marshalGeneralNames([]GeneralName{URIName(crlURL)})
		if err != nil {
			return nil, err
		}
		var names asn1.RawValue
		if _, err := asn1.Unmarshal(uri, &names); err != nil {
			return nil, fmt.Errorf("certs: decode CRL distribution name: %w", err)
		}
		der, err := asn1.Marshal([]struct {
			DistributionPoint struct {
				FullName asn1.RawValue
			} `asn1:"tag:0"`
		}{{DistributionPoint: struct{ FullName asn1.RawValue }{asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: names.Bytes}}}})
		if err != nil {
			return nil, fmt.Errorf("certs: encode CRL distribution point: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: oidCRLDistributionPoints, Value: der})
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, issuer.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("certs: sign leaf: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certs: parse generated leaf: %w", err)
	}
	return NewCert(certificate), nil
}

func sha256SignatureAlgorithm(key crypto.Signer) (x509.SignatureAlgorithm, error) {
	if key == nil {
		return 0, errors.New("certs: missing signing key")
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		return x509.SHA256WithRSA, nil
	case *ecdsa.PublicKey:
		return x509.ECDSAWithSHA256, nil
	default:
		return 0, fmt.Errorf("certs: key type %T does not support SHA-256 signing", key.Public())
	}
}

func marshalGeneralNames(names []GeneralName) ([]byte, error) {
	raw := make([]asn1.RawValue, 0, len(names))
	for _, name := range names {
		value := asn1.RawValue{Class: 2}
		switch name.typ {
		case GeneralNameDNS, GeneralNameEmail, GeneralNameURI:
			for _, b := range []byte(name.text) {
				if b > 127 {
					return nil, errors.New("certs: DNS, email and URI names must be ASCII")
				}
			}
			value.Bytes = []byte(name.text)
			switch name.typ {
			case GeneralNameDNS:
				value.Tag = 2
			case GeneralNameEmail:
				value.Tag = 1
			case GeneralNameURI:
				value.Tag = 6
			}
		case GeneralNameIP:
			if !name.ip.IsValid() {
				return nil, errors.New("certs: invalid IP address in SAN")
			}
			value.Tag, value.Bytes = 7, name.ip.AsSlice()
		case GeneralNameOther:
			value.FullBytes = []byte(name.text)
		default:
			return nil, fmt.Errorf("certs: unsupported general name type %d", name.typ)
		}
		raw = append(raw, value)
	}
	der, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("certs: encode subject alternative names: %w", err)
	}
	return der, nil
}
