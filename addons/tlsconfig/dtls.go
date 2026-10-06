// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	dtls "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/options"
)

func (t *TLSConfig) dtlsStartClient(_ context.Context, d *hookdata.TLS) error {
	if d.DTLSConfig != nil || d.Config != nil {
		return nil // The layer validates wrong-transport overrides before handshaking.
	}
	if err := t.dtlsVersionWindow("client"); err != nil {
		return err
	}
	client, server := d.Context.Client, d.Context.Server
	if len(client.CipherList) == 0 {
		if ciphers := t.options.OptStr("ciphers_client"); ciphers != nil {
			client.CipherList = strings.Split(*ciphers, ":")
		}
	}
	cfg, err := t.dtlsConfig("client", client.CipherList)
	if err != nil {
		return err
	}
	entry, err := t.getCert(d.Context)
	if err != nil {
		return err
	}
	var upstream [][]byte
	if t.options.Bool("add_upstream_certs_to_client_chain") {
		upstream = server.CertificateList
	}
	cfg.GetCertificate, err = dtlsCertificateCallback(t.store, entry, upstream)
	if err != nil {
		return err
	}
	if t.options.Bool("request_client_cert") {
		cfg.ClientAuth = dtls.RequestClientCert
	}
	if proto := alpnSelect(client.ALPN, server.ALPN, client.ALPNOffers, t.options.Bool("http2")); proto != nil {
		cfg.SupportedProtocols = []string{string(proto)}
	}
	client.MitmCert = entry.Cert.PEM()
	d.DTLSConfig = cfg
	return nil
}

func (t *TLSConfig) dtlsStartServer(_ context.Context, d *hookdata.TLS) error {
	if d.DTLSConfig != nil || d.Config != nil {
		return nil
	}
	if err := t.dtlsVersionWindow("server"); err != nil {
		return err
	}
	client, server := d.Context.Client, d.Context.Server
	if server.Address == nil {
		return fmt.Errorf("tlsconfig: starting server DTLS without a server address")
	}
	if server.SNI == nil {
		sni := server.Address.Host
		if client.SNI != nil && *client.SNI != "" {
			sni = *client.SNI
		}
		server.SNI = new(sni)
	}
	if len(server.ALPNOffers) == 0 {
		server.ALPNOffers = serverALPNOffers(client.ALPNOffers, t.options.Bool("http2"))
	}
	if len(server.CipherList) == 0 {
		if ciphers := t.options.OptStr("ciphers_server"); ciphers != nil {
			server.CipherList = strings.Split(*ciphers, ":")
		}
	}
	cfg, err := t.dtlsConfig("server", server.CipherList)
	if err != nil {
		return err
	}
	if path := t.options.OptStr("client_certs"); path != nil {
		cert, err := clientCertificate(expandUser(*path), server)
		if err != nil {
			return err
		}
		if cert != nil {
			cfg.Certificates = append(cfg.Certificates, *cert)
		}
	}
	cfg.InsecureSkipVerify = t.options.Bool("ssl_insecure")
	if !cfg.InsecureSkipVerify {
		cfg.RootCAs, err = trustedRoots(t.options.OptStr("ssl_verify_upstream_trusted_ca"), t.options.OptStr("ssl_verify_upstream_trusted_confdir"))
		if err != nil {
			return err
		}
		if *server.SNI == "" {
			return fmt.Errorf("Cannot validate certificate hostname without SNI") //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
	}
	if sni := *server.SNI; sni != "" {
		cfg.ServerName = sni
		if _, err := netip.ParseAddr(sni); err != nil {
			cfg.ServerName, err = encodeIDNA(sni)
			if err != nil {
				return fmt.Errorf("tlsconfig: server name %q: %w", sni, err)
			}
		}
	}
	for _, offer := range server.ALPNOffers {
		cfg.SupportedProtocols = append(cfg.SupportedProtocols, string(offer))
	}
	d.DTLSConfig = cfg
	return nil
}

// dtlsVersionWindow accepts only TLS-option windows that include TLS 1.2,
// from which DTLS 1.2 is derived (RFC 6347). It does not restrict ordinary TLS.
func (t *TLSConfig) dtlsVersionWindow(side string) error {
	minVersion := t.options.Str("tls_version_" + side + "_min")
	maxVersion := t.options.Str("tls_version_" + side + "_max")
	if minVersion == "TLS1_3" || maxVersion == "SSL3" || maxVersion == "TLS1" || maxVersion == "TLS1_1" {
		return fmt.Errorf("DTLS in mitmproxy-go supports DTLS 1.2 only; tls_version_%s_min=%s and tls_version_%s_max=%s exclude it.", side, minVersion, side, maxVersion) //nolint:staticcheck // Fixed user-facing version diagnostic.
	}
	return nil
}

// dtlsConfig maps transport-independent TLS options onto the pinned DTLS
// implementation; unsupported restrictions fail rather than being ignored.
func (t *TLSConfig) dtlsConfig(side string, ciphers []string) (*dtls.Config, error) { //nolint:staticcheck // Frozen hooks allow mutable DTLS config overrides.
	cfg := &dtls.Config{KeyLogWriter: t.keyLog()} //nolint:staticcheck // Frozen hooks allow mutable DTLS config overrides.
	if len(ciphers) > 0 {
		ids, err := suiteIDs("ciphers_"+side, ciphers)
		if err != nil {
			return nil, err
		}
		available := append(dtls.CipherSuites(), dtls.InsecureCipherSuites()...)
		for i, id := range ids {
			if !slices.ContainsFunc(available, func(suite *tls.CipherSuite) bool { return suite.ID == id }) {
				return nil, options.Errorf("ciphers_%s: %q is not supported by DTLS", side, ciphers[i])
			}
			cfg.CipherSuites = append(cfg.CipherSuites, dtls.CipherSuiteID(id))
		}
	}
	if name := t.options.OptStr("tls_ecdh_curve_" + side); name != nil {
		switch *name {
		case "secp256r1":
			cfg.EllipticCurves = []elliptic.Curve{elliptic.P256}
		case "secp384r1":
			cfg.EllipticCurves = []elliptic.Curve{elliptic.P384}
		default:
			return nil, options.Errorf("tls_ecdh_curve_%s: %q is not supported by DTLS", side, *name)
		}
	}
	return cfg, nil
}
