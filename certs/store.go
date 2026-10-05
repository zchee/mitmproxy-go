// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto"
	"slices"
)

// Entry is one certificate the store can serve: the leaf, the private
// key it is served with, and the chain sent after it. ChainFile is the
// path the chain was read from, or "" when the chain is the store's
// default CA alone.
type Entry struct {
	Cert       *Cert
	PrivateKey crypto.Signer
	ChainFile  string
	ChainCerts []*Cert
}

// storeCap is how many generated entries a [Store] keeps before the
// oldest is expired. Each store copies it into an unexported field, so a
// test can lower its own store's cap.
const storeCap = 100

// Store is an in-memory certificate store. [Store.GetCert] serves a
// certificate for a requested name, generating one with [DummyCert]
// under the store's CA when neither a configured certificate nor an
// already generated one matches; generated entries are kept up to a cap
// of 100 and then expired first-in first-out.
//
// A Store synchronises itself: all methods are safe for concurrent use.
// The mutex is held across certificate generation, so two requests for
// the same new name wait for one generation.
type Store struct {
	defaultPrivateKey crypto.Signer
	defaultCA         *Cert
	defaultChainFile  string
	defaultChainCerts []*Cert
	defaultCRL        []byte
}

// DefaultCA returns the store's CA certificate.
func (s *Store) DefaultCA() *Cert {
	return s.defaultCA
}

// DefaultPrivateKey returns the CA private key, which also signs every
// generated leaf.
func (s *Store) DefaultPrivateKey() crypto.Signer {
	return s.defaultPrivateKey
}

// DefaultChainFile returns the path of the PEM file whose certificates
// are sent as the default chain, or "" when the store was loaded from a
// file holding only the CA certificate.
func (s *Store) DefaultChainFile() string {
	return s.defaultChainFile
}

// DefaultChainCerts returns the certificates of the default chain: the
// certificates of [Store.DefaultChainFile], or the CA alone.
func (s *Store) DefaultChainCerts() []*Cert {
	return slices.Clone(s.defaultChainCerts)
}

// DefaultCRL returns the DER-encoded empty certificate revocation list
// signed by the CA, which the proxy serves at the CRL distribution point
// of its generated leaves.
func (s *Store) DefaultCRL() []byte {
	return slices.Clone(s.defaultCRL)
}
