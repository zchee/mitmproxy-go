// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // Read existing PBES2 keys encrypted with triple DES.
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // PBKDF2-HMAC-SHA1 is specified by existing encrypted key files.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
)

const (
	maxPEMSize          = 8 * 1024 * 1024
	maxPBKDF2Iterations = 1_000_000
)

func loadPEMPrivateKey(raw, password []byte) (crypto.Signer, error) {
	if len(raw) > maxPEMSize {
		return nil, errors.New("certs: PEM input exceeds 8 MiB")
	}
	for len(raw) != 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		raw = rest
		switch block.Type {
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		default:
			continue
		}
		der := block.Bytes
		var err error
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			if password == nil {
				return nil, ErrPassphraseRequired
			}
			der, err = decryptPKCS8(der, password)
		} else if block.Headers["DEK-Info"] != "" {
			if password == nil {
				return nil, ErrPassphraseRequired
			}
			der, err = x509.DecryptPEMBlock(block, password) //nolint:staticcheck // Loading legacy encrypted PEM is required for existing configurations.
		}
		if err != nil {
			return nil, fmt.Errorf("certs: decrypt private key: %w", err)
		}
		var key any
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(der)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(der)
		default:
			key, err = x509.ParsePKCS8PrivateKey(der)
		}
		if err != nil {
			return nil, fmt.Errorf("certs: parse private key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("certs: private key type %T cannot sign certificates", key)
		}
		return signer, nil
	}
	return nil, errors.New("certs: no PEM private key found")
}

func decryptPKCS8(der, password []byte) ([]byte, error) {
	var encrypted struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	if err := unmarshalPrivateKeyDER(der, &encrypted); err != nil {
		return nil, err
	}
	if encrypted.Algorithm.Algorithm.String() != "1.2.840.113549.1.5.13" {
		return nil, errors.New("certs: encrypted PKCS#8 requires PBES2")
	}
	var params struct {
		KDF    pkix.AlgorithmIdentifier
		Cipher pkix.AlgorithmIdentifier
	}
	if err := unmarshalPrivateKeyDER(encrypted.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}
	if params.KDF.Algorithm.String() != "1.2.840.113549.1.5.12" {
		return nil, errors.New("certs: PBES2 requires PBKDF2")
	}
	var kdf struct {
		Salt       []byte
		Iterations int
		KeyLength  int                      `asn1:"optional"`
		PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	if err := unmarshalPrivateKeyDER(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, err
	}
	if kdf.Iterations < 1 || kdf.Iterations > maxPBKDF2Iterations || len(kdf.Salt) > 1024 {
		return nil, errors.New("certs: PBKDF2 parameters exceed supported limits")
	}
	var newHash func() hash.Hash
	switch kdf.PRF.Algorithm.String() {
	case "", "1.2.840.113549.2.7":
		newHash = sha1.New
	case "1.2.840.113549.2.8":
		newHash = sha256.New224
	case "1.2.840.113549.2.9":
		newHash = sha256.New
	case "1.2.840.113549.2.10":
		newHash = sha512.New384
	case "1.2.840.113549.2.11":
		newHash = sha512.New
	default:
		return nil, errors.New("certs: unsupported PBKDF2 hash")
	}
	keyLength := 0
	var newCipher func([]byte) (cipher.Block, error)
	switch params.Cipher.Algorithm.String() {
	case "2.16.840.1.101.3.4.1.2":
		keyLength, newCipher = 16, aes.NewCipher
	case "2.16.840.1.101.3.4.1.22":
		keyLength, newCipher = 24, aes.NewCipher
	case "2.16.840.1.101.3.4.1.42":
		keyLength, newCipher = 32, aes.NewCipher
	case "1.2.840.113549.3.7":
		keyLength, newCipher = 24, des.NewTripleDESCipher //nolint:gosec // Existing upstream encrypted PKCS#8 fixture uses triple DES.
	default:
		return nil, errors.New("certs: unsupported PBES2 cipher")
	}
	if kdf.KeyLength != 0 && kdf.KeyLength != keyLength {
		return nil, errors.New("certs: PBKDF2 key length does not match cipher")
	}
	var iv []byte
	if err := unmarshalPrivateKeyDER(params.Cipher.Parameters.FullBytes, &iv); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(newHash, string(password), kdf.Salt, kdf.Iterations, keyLength)
	if err != nil {
		return nil, fmt.Errorf("certs: derive private-key encryption key: %w", err)
	}
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(encrypted.Data) == 0 || len(encrypted.Data)%block.BlockSize() != 0 {
		return nil, errors.New("certs: invalid encrypted private-key block length")
	}
	plain := make([]byte, len(encrypted.Data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, encrypted.Data)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > block.BlockSize() {
		return nil, errors.New("certs: invalid private-key password or padding")
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			return nil, errors.New("certs: invalid private-key password or padding")
		}
	}
	return plain[:len(plain)-padding], nil
}

func unmarshalPrivateKeyDER(der []byte, out any) error {
	rest, err := asn1.Unmarshal(der, out)
	if err != nil {
		return fmt.Errorf("certs: invalid encrypted private-key DER: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("certs: trailing encrypted private-key DER")
	}
	return nil
}
