// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// AddCertFile loads a PEM certificate and key and registers it for spec, its
// CN, and its SANs. The file may include a chain. A missing or invalid key uses
// the default key only when its public key matches the certificate; an encrypted
// key without a passphrase returns ErrPassphraseRequired instead. Invalid chains
// warn and fall back to the first certificate. Files are limited to 8 MiB.
func (s *Store) AddCertFile(spec, path string, passphrase []byte) error {
	raw, err := readPEMFile(path)
	if err != nil {
		return err
	}
	cert, err := ParseCert(raw)
	if err != nil {
		return err
	}
	key, keyErr := loadPEMPrivateKey(raw, passphrase)
	if errors.Is(keyErr, ErrPassphraseRequired) {
		return keyErr
	}
	if keyErr != nil {
		key = s.defaultPrivateKey
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	matches := false
	if key != nil {
		public, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
		matches = ok && public.Equal(cert.X509().PublicKey)
	}
	if !matches {
		if keyErr != nil {
			return fmt.Errorf("Unable to find private key in \"%s\": %w", absolute, keyErr) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
		return fmt.Errorf("Private and public keys in \"%s\" do not match", absolute) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
	chain, err := parsePEMCertificates(raw)
	if err != nil {
		slog.Warn("Failed to read certificate chain: " + err.Error())
		chain = []*Cert{cert}
	}
	if cert.IsCA() {
		slog.Warn(fmt.Sprintf("\"%s\" is a certificate authority and not a leaf certificate. This indicates a misconfiguration, see https://docs.mitmproxy.org/stable/concepts-certificates/.", absolute))
	}
	s.AddCert(&Entry{Cert: cert, PrivateKey: key, ChainFile: path, ChainCerts: chain}, spec)
	return nil
}

// AddCertSpec loads the certs option's [domain=]path form. A missing domain
// defaults to "*"; only the first equals sign splits the spec. Leading ~ and
// ~user paths are expanded. Errors retain mitmproxy's missing-file and invalid-
// format prefixes; ErrPassphraseRequired and filesystem errors remain distinct.
func (s *Store) AddCertSpec(spec string, passphrase []byte) error {
	name, path, found := strings.Cut(spec, "=")
	if !found {
		name, path = "*", spec
	}
	if strings.HasPrefix(path, "~") {
		username, rest, _ := strings.Cut(filepath.ToSlash(path[1:]), "/")
		var home string
		var err error
		if username == "" {
			home, err = os.UserHomeDir()
		} else {
			var account *user.User
			account, err = user.Lookup(username)
			if err == nil {
				home = account.HomeDir
			}
		}
		if err != nil {
			return fmt.Errorf("Could not determine home directory: %w", err) //nolint:staticcheck // Preserve pathlib's user-facing diagnostic.
		}
		path = filepath.Join(home, rest)
	}
	path = filepath.Clean(path)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("Certificate file does not exist: %s", path) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
		return err
	}
	if err := s.AddCertFile(name, path, passphrase); err != nil {
		if errors.Is(err, ErrPassphraseRequired) {
			return err
		}
		if _, ok := errors.AsType[*os.PathError](err); ok {
			return err
		}
		return fmt.Errorf("Invalid certificate format for %s: %w", path, err) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
	return nil
}

func readPEMFile(path string) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // The caller explicitly selects its certificate file.
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPEMSize+1))
	if err := errors.Join(err, file.Close()); err != nil {
		return nil, err
	}
	if len(raw) > maxPEMSize {
		return nil, errors.New("certs: PEM input exceeds 8 MiB")
	}
	return raw, nil
}

func parsePEMCertificates(raw []byte) ([]*Cert, error) {
	const begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	var certificates []*Cert
	for {
		_, rest, found := bytes.Cut(raw, []byte(begin))
		if !found {
			break
		}
		body, after, found := bytes.Cut(rest, []byte(end))
		if !found || bytes.Contains(body, []byte(begin)) {
			return nil, errors.New("certs: malformed certificate PEM block")
		}
		block, _ := pem.Decode(append(append([]byte(begin), body...), []byte(end)...))
		if block == nil {
			return nil, errors.New("certs: malformed certificate PEM block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certs: parse certificate chain: %w", err)
		}
		certificates = append(certificates, NewCert(certificate))
		raw = after
	}
	if len(certificates) == 0 {
		return nil, errors.New("certs: no CERTIFICATE block in PEM data")
	}
	return certificates, nil
}
