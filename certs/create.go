// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RFC 5280 key identifiers use SHA-1, not certificate signatures.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
	"unicode/utf8"
)

// CreateCA creates a self-signed RSA certificate authority with the given
// organization, common name and key size in bits. Its validity is [CAExpiry],
// backdated by [ValidityOffset], and its signature uses SHA-256. It returns
// the private key and certificate, or an error for invalid input or encoding.
func CreateCA(organization, commonName string, keySize int) (*rsa.PrivateKey, *Cert, error) {
	notBefore := time.Now().UTC().Add(ValidityOffset)
	subject, err := marshalSubject([]nameAttr{{oid: oidCommonName, val: commonName}, {oid: oidOrganization, val: organization}})
	if err != nil {
		return nil, nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: generate CA key: %w", err)
	}
	ski, err := publicKeyID(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	skiDER, err := asn1.Marshal(ski)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: encode CA key identifier: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          newSerial(),
		RawSubject:            subject,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(CAExpiry),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
		// Explicit extensions preserve upstream's order and prevent Go's
		// default truncated-SHA-256 subject key identifier from replacing it.
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 3, 1, 1, 0xff}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 10, 6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 1}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{3, 2, 1, 6}},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: skiDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: sign CA: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: parse generated CA: %w", err)
	}
	return key, NewCert(certificate), nil
}

func newSerial() *big.Int {
	var raw [20]byte
	for {
		_, _ = rand.Read(raw[:]) // crypto/rand.Read always fills the buffer or terminates the process.
		raw[0] &= 0x7f
		serial := new(big.Int).SetBytes(raw[:])
		if serial.Sign() > 0 {
			return serial
		}
	}
}

func marshalSubject(attrs []nameAttr) ([]byte, error) {
	name := make(pkix.RDNSequence, 0, len(attrs))
	for _, attr := range attrs {
		if !utf8.ValidString(attr.val) {
			return nil, errors.New("certs: subject attribute is not valid UTF-8")
		}
		if attr.oid.Equal(oidCommonName) && (len(attr.val) == 0 || len(attr.val) > 64) {
			return nil, errors.New("certs: common name must contain between 1 and 64 UTF-8 bytes")
		}
		name = append(name, pkix.RelativeDistinguishedNameSET{{
			Type:  attr.oid,
			Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(attr.val)},
		}})
	}
	der, err := asn1.Marshal(name)
	if err != nil {
		return nil, fmt.Errorf("certs: encode subject: %w", err)
	}
	return der, nil
}

func publicKeyID(key crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("certs: encode public key: %w", err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("certs: decode public key bits: %w", err)
	}
	// RFC 5280 section 4.2.1.2 hashes the subjectPublicKey bits, excluding
	// the BIT STRING tag, length and unused-bits count.
	digest := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // Identifies a key; not used as a signature hash.
	return digest[:], nil
}
