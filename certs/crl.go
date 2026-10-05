// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

func dummyCRL(privateKey crypto.Signer, ca *Cert) ([]byte, error) {
	if ca == nil || ca.X509() == nil {
		return nil, errors.New("certs: missing CA certificate")
	}
	algorithm, err := sha256SignatureAlgorithm(privateKey)
	if err != nil {
		return nil, err
	}
	// Go requires signing usage and an SKI. Copy the metadata because callers
	// may share the CA, and upstream permits legacy CAs without either field.
	issuer := *ca.X509()
	issuer.Subject, issuer.RawSubject = issuer.Issuer, issuer.RawIssuer
	issuer.KeyUsage |= x509.KeyUsageCRLSign
	if len(issuer.SubjectKeyId) == 0 {
		issuer.SubjectKeyId, err = publicKeyID(issuer.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	notBefore := time.Now().UTC().Add(ValidityOffset)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: algorithm,
		Number:             big.NewInt(1000),
		ThisUpdate:         notBefore,
		NextUpdate:         notBefore.Add(CRLExpiry),
	}, &issuer, privateKey)
	if err != nil {
		return nil, fmt.Errorf("certs: sign CRL: %w", err)
	}
	return der, nil
}
