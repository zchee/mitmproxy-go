// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// tlsPolicy owns wire values and shares only immutable signing material.
type tlsPolicy struct {
	alpn           []string
	certificates   [][]byte
	privateKey     crypto.PrivateKey
	serverName     string
	caFile, caPath *string
	verify         hookdata.VerifyMode
}

func startPolicy(ctx context.Context, c *layer.Context, client bool) (tlsPolicy, error) {
	data := &hookdata.QUICTLS{}
	var hook addon.Hook = addon.QUICStartServerHook{Data: data}
	if client {
		hook = addon.QUICStartClientHook{Data: data}
	}
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Context, data.Conn = c.Data, &c.Data.Server.Connection
		if client {
			data.Conn = &c.Data.Client.Connection
		}
		return nil
	}, hook); err != nil {
		return tlsPolicy{}, err
	}
	var policy tlsPolicy
	err := c.Do(ctx, func(context.Context) error {
		if data.Settings == nil {
			return errors.New("No QUIC context was provided, failing connection.") //nolint:staticcheck // Preserve the upstream QUIC startup diagnostic.
		}
		s := data.Settings
		policy.alpn = slices.Clone(s.ALPNProtocols)
		policy.verify = hookdata.VerifyRequired
		if client {
			policy.verify = hookdata.VerifyNone
		}
		if s.VerifyMode != nil {
			policy.verify = *s.VerifyMode
		}
		if s.CAFile != nil {
			policy.caFile = new(*s.CAFile)
		}
		if s.CAPath != nil {
			policy.caPath = new(*s.CAPath)
		}
		if data.Conn.SNI != nil {
			policy.serverName = *data.Conn.SNI
		} else if !client && c.Data.Server.Address != nil {
			policy.serverName = c.Data.Server.Address.Host
		}
		if s.Certificate != nil {
			policy.certificates = append(policy.certificates, bytes.Clone(s.Certificate.Raw))
		}
		for _, cert := range s.CertificateChain {
			if cert == nil {
				return errors.New("quic: nil certificate in chain")
			}
			policy.certificates = append(policy.certificates, bytes.Clone(cert.Raw))
		}
		policy.privateKey = s.CertificatePrivateKey
		return nil
	})
	return policy, err
}

func (p tlsPolicy) config(client bool) (*tls.Config, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: p.alpn, ServerName: p.serverName}
	if len(p.certificates) != 0 {
		conf.Certificates = []tls.Certificate{{Certificate: p.certificates, PrivateKey: p.privateKey}}
	}
	var roots *x509.CertPool
	if p.caFile != nil || p.caPath != nil {
		roots = x509.NewCertPool()
		paths := []string{}
		if p.caFile != nil {
			paths = append(paths, *p.caFile)
		}
		if p.caPath != nil {
			dir := expandTrustPath(*p.caPath)
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, fmt.Errorf("quic: trusted CA directory: %w", err)
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					paths = append(paths, filepath.Join(dir, entry.Name()))
				}
			}
		}
		for _, path := range paths {
			required := p.caFile != nil && path == *p.caFile
			pem, err := os.ReadFile(filepath.Clean(expandTrustPath(path)))
			if err != nil {
				if required {
					return nil, fmt.Errorf("quic: trusted CA: %w", err)
				}
				continue
			}
			if !roots.AppendCertsFromPEM(pem) && required {
				return nil, errors.New("quic: trusted CA contains no certificates")
			}
		}
	}
	if client {
		conf.ClientCAs = roots
		// aioquic servers default to no client-certificate requirement.
		conf.ClientAuth = tls.NoClientCert
		if p.verify == hookdata.VerifyOptional {
			conf.ClientAuth = tls.VerifyClientCertIfGiven
		}
		if p.verify == hookdata.VerifyRequired {
			conf.ClientAuth = tls.RequireAndVerifyClientCert
		}
	} else {
		conf.RootCAs = roots
		conf.InsecureSkipVerify = p.verify == hookdata.VerifyNone
	}
	return conf, nil
}

func expandTrustPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + path[1:]
		}
	}
	return path
}
