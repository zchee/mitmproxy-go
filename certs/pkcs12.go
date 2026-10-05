// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func encodePKCS12(key crypto.Signer, ca *Cert, friendlyName string) (keyBundle, certBundle []byte, err error) {
	keyBundle, err = pkcs12.Passwordless.Encode(key, ca.X509(), nil, "")
	if err != nil {
		return nil, nil, fmt.Errorf("certs: encode key-bearing PKCS#12: %w", err)
	}
	certBundle, err = pkcs12.Passwordless.EncodeTrustStoreEntries([]pkcs12.TrustStoreEntry{{Cert: ca.X509(), FriendlyName: friendlyName}}, "")
	if err != nil {
		return nil, nil, fmt.Errorf("certs: encode certificate-only PKCS#12: %w", err)
	}
	return keyBundle, certBundle, nil
}
