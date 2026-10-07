// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
)

// QUICStartClient supplies the client-facing QUIC TLS settings under dispatch.
// Settings already supplied by another addon are left untouched. Certificate,
// chain, private key and ALPN follow py:mitmproxy/addons/tlsconfig.py:379-417.
func (t *TLSConfig) QUICStartClient(_ context.Context, d *hookdata.QUICTLS) error {
	if d.Settings != nil {
		return nil
	}
	client, server := d.Context.Client, d.Context.Server
	entry, err := t.getCert(d.Context)
	if err != nil {
		return err
	}
	if len(client.CipherList) == 0 {
		if ciphers := t.options.OptStr("ciphers_client"); ciphers != nil {
			client.CipherList = strings.Split(*ciphers, ":")
		}
	}
	settings := &hookdata.QUICTLSSettings{
		Certificate:           entry.Cert.X509(),
		CertificatePrivateKey: entry.PrivateKey,
	}
	if len(client.CipherList) > 0 {
		settings.CipherSuites, err = suiteIDs("ciphers_client", client.CipherList)
		if err != nil {
			return err
		}
	}
	var selected [][]byte
	for _, alpn := range [][]byte{client.ALPN, server.ALPN} {
		if len(alpn) > 0 {
			selected = append(selected, alpn)
		}
	}
	if len(selected) == 0 {
		selected = client.ALPNOffers
	}
	settings.ALPNProtocols, err = quicALPN(selected)
	if err != nil {
		return err
	}
	for _, chain := range entry.ChainCerts {
		settings.CertificateChain = append(settings.CertificateChain, chain.X509())
	}
	if t.options.Bool("add_upstream_certs_to_client_chain") {
		for _, pemCert := range server.CertificateList {
			chain, err := certs.ParseCert(pemCert)
			if err != nil {
				return fmt.Errorf("tlsconfig: upstream certificate: %w", err)
			}
			settings.CertificateChain = append(settings.CertificateChain, chain.X509())
		}
	}
	d.Settings = settings
	return nil
}

// QUICStartServer supplies origin-facing QUIC TLS settings under dispatch.
// Settings already supplied by another addon are left untouched. Verification,
// SNI, ALPN and trust paths follow py:mitmproxy/addons/tlsconfig.py:419-464.
// Client certificates are not installed, matching upstream QUIC behavior.
func (t *TLSConfig) QUICStartServer(_ context.Context, d *hookdata.QUICTLS) error {
	if d.Settings != nil {
		return nil
	}
	client, server := d.Context.Client, d.Context.Server
	if server.Address == nil {
		return fmt.Errorf("tlsconfig: starting server QUIC without a server address")
	}
	mode := hookdata.VerifyRequired
	if t.options.Bool("ssl_insecure") {
		mode = hookdata.VerifyNone
	}
	settings := &hookdata.QUICTLSSettings{
		VerifyMode: new(mode),
		CAPath:     t.options.OptStr("ssl_verify_upstream_trusted_confdir"),
		CAFile:     t.options.OptStr("ssl_verify_upstream_trusted_ca"),
	}
	if server.SNI == nil {
		sni := server.Address.Host
		if client.SNI != nil && *client.SNI != "" {
			sni = *client.SNI
		}
		server.SNI = new(sni)
	}
	if len(server.ALPNOffers) == 0 {
		if len(client.ALPNOffers) > 0 {
			for _, offer := range client.ALPNOffers {
				server.ALPNOffers = append(server.ALPNOffers, bytes.Clone(offer))
			}
		} else {
			// aioquic/h3/connection.py H3_ALPN is ["h3"] in the pinned 1.2.0.
			server.ALPNOffers = [][]byte{[]byte("h3")}
		}
	}
	if len(server.CipherList) == 0 {
		if ciphers := t.options.OptStr("ciphers_server"); ciphers != nil {
			server.CipherList = strings.Split(*ciphers, ":")
		}
	}
	var err error
	if len(server.CipherList) > 0 {
		settings.CipherSuites, err = suiteIDs("ciphers_server", server.CipherList)
		if err != nil {
			return err
		}
	}
	settings.ALPNProtocols, err = quicALPN(server.ALPNOffers)
	if err != nil {
		return err
	}
	d.Settings = settings
	return nil
}

func quicALPN(protocols [][]byte) ([]string, error) {
	if protocols == nil {
		return nil, nil
	}
	out := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		for _, b := range protocol {
			if b > 127 {
				return nil, fmt.Errorf("tlsconfig: QUIC ALPN is not ASCII")
			}
		}
		out = append(out, string(protocol))
	}
	return out, nil
}
