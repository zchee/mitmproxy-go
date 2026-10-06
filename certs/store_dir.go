// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FromStore loads the certificate store of the configuration directory
// path, creating the directory and a fresh CA named basename when
// `<basename>-ca.pem` does not exist yet. A created directory holds
// mitmproxy's complete file set: `<basename>-ca.pem` (PKCS#1 private key
// followed by the CA certificate, readable by the owner only, like
// `<basename>-ca.p12`), `<basename>-ca-cert.pem` and the byte-identical
// `<basename>-ca-cert.cer`, `<basename>-ca-cert.p12`, and
// `<basename>-dhparam.pem` holding [DefaultDHParam]. Loading an existing
// directory preserves the CA identity; passphrase decrypts an encrypted
// CA file as [FromFiles] describes.
func FromStore(path, basename string, keySize int, passphrase []byte) (*Store, error) {
	caFile := filepath.Join(path, basename+"-ca.pem")
	dhparamFile := filepath.Join(path, basename+"-dhparam.pem")
	if _, err := os.Stat(caFile); errors.Is(err, os.ErrNotExist) {
		if err := createStore(path, basename, keySize); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return FromFiles(caFile, dhparamFile, passphrase)
}

// FromFiles loads a store whose CA file holds the private key and the CA
// certificate, with any further certificates serving as the default
// chain: the store's ChainFile is caFile only when it holds more than
// one certificate. A missing DH parameter file is recreated with
// [DefaultDHParam], as mitmproxy does for configuration directories
// older than its 0.11 layout. An encrypted private key without a
// passphrase returns [ErrPassphraseRequired]. The CA file is limited to
// 8 MiB.
func FromFiles(caFile, dhparamFile string, passphrase []byte) (*Store, error) {
	raw, err := readPEMFile(caFile)
	if err != nil {
		return nil, err
	}
	key, err := loadPEMPrivateKey(raw, passphrase)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(dhparamFile); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := checkStoreDirectory(filepath.Dir(dhparamFile)); err != nil {
			return nil, err
		}
		if err := writeStoreFile(dhparamFile, []byte(DefaultDHParam), 0o600); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	chain, err := parsePEMCertificates(raw)
	if err != nil {
		return nil, err
	}
	ca := chain[0]
	crl, err := dummyCRL(key, ca)
	if err != nil {
		return nil, err
	}
	chainFile := ""
	if len(chain) > 1 {
		chainFile = caFile
	}
	return &Store{
		defaultPrivateKey: key,
		defaultCA:         ca,
		defaultChainFile:  chainFile,
		defaultChainCerts: chain,
		defaultCRL:        crl,
		cap:               storeCap,
	}, nil
}

// createStore writes a new CA without replacing existing store files. Key
// files and DH parameters are owner-only; certificates use the process umask.
func createStore(path, basename string, keySize int) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := checkStoreDirectory(path); err != nil {
		return err
	}
	key, ca, err := CreateCA(basename, basename, keySize)
	if err != nil {
		return err
	}
	keyBundle, certBundle, err := encodePKCS12(key, ca, basename)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := ca.PEM()
	files := []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{
		{basename + "-ca.pem", append(keyPEM, certPEM...), 0o600},
		{basename + "-ca.p12", keyBundle, 0o600},
		{basename + "-ca-cert.pem", certPEM, 0o666},
		{basename + "-ca-cert.cer", certPEM, 0o666},
		{basename + "-ca-cert.p12", certBundle, 0o666},
		{basename + "-dhparam.pem", []byte(DefaultDHParam), 0o600},
	}
	for _, file := range files {
		if err := writeStoreFile(filepath.Join(path, file.name), file.content, file.mode); err != nil {
			if errors.Is(err, os.ErrExist) {
				if file.name == basename+"-ca.pem" {
					// Another creator owns this CA identity and its companion files.
					return nil
				}
				continue
			}
			return fmt.Errorf("certs: write %s: %w", file.name, err)
		}
	}
	return nil
}

func writeStoreFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // Public certificates use the process umask; secret files pass 0600.
	if err != nil {
		return err
	}
	_, err = file.Write(content)
	return errors.Join(err, file.Close())
}
