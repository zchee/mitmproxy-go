// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package tlsconfig supplies the proxy core with the TLS configurations it
// uses to negotiate TLS, as upstream's tlsconfig addon supplies it with
// OpenSSL connection objects (py:mitmproxy/addons/tlsconfig.py).
//
// The addon builds every *tls.Config inside the tls_start_client and
// tls_start_server hooks, under the dispatch lock, and returns early when a
// user addon already set one. The TLS layer uses the configuration unchanged.
// Certificates come from a certs.Store; the leaf presented to a client is
// chosen from the upstream certificate's names, the client's SNI and the
// server address, and is published as the client connection's MitmCert. The
// addon also answers requests for the certificate revocation list of its CA
// from the request hook.
package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/options"
)

// TLSConfig builds the TLS configurations of client and server connections
// from the TLS options and the proxy's certificate store.
//
// All methods run inside the addon dispatch domain, so they need no lock of
// their own; the certificate store synchronises itself.
type TLSConfig struct {
	options *options.Manager
	store   *certs.Store

	keyLogOnce   sync.Once
	keyLogWriter io.WriteCloser
}

// New returns the addon using opts.
func New(opts *options.Manager) *TLSConfig {
	return &TLSConfig{options: opts}
}

// Load registers the TLS options, exactly as upstream's tlsconfig addon
// registers them (py:mitmproxy/addons/tlsconfig.py:136-202).
func (t *TLSConfig) Load(ctx context.Context, l *addon.Loader) error {
	insecure := strings.Join(insecureTLSMinVersions[:len(insecureTLSMinVersions)-1], ", ") +
		" and " + insecureTLSMinVersions[len(insecureTLSMinVersions)-1]
	for _, o := range []struct {
		name    string
		typ     options.Type
		def     any
		help    string
		choices []string
	}{
		{"tls_version_client_min", options.TypeStr, "TLS1_2", "Set the minimum TLS version for client connections. " + insecure + " are insecure.", tlsVersionNames},
		{"tls_version_client_max", options.TypeStr, "UNBOUNDED", "Set the maximum TLS version for client connections.", tlsVersionNames},
		{"tls_version_server_min", options.TypeStr, "TLS1_2", "Set the minimum TLS version for server connections. " + insecure + " are insecure.", tlsVersionNames},
		{"tls_version_server_max", options.TypeStr, "UNBOUNDED", "Set the maximum TLS version for server connections.", tlsVersionNames},
		{"tls_ecdh_curve_client", options.TypeOptStr, nil, "Use a specific elliptic curve for ECDHE key exchange on client connections. " + `OpenSSL syntax, for example "prime256v1" (see ` + "`openssl ecparam -list_curves`).", nil},
		{"tls_ecdh_curve_server", options.TypeOptStr, nil, "Use a specific elliptic curve for ECDHE key exchange on server connections. " + `OpenSSL syntax, for example "prime256v1" (see ` + "`openssl ecparam -list_curves`).", nil},
		{"request_client_cert", options.TypeBool, false, "Requests a client certificate (TLS message 'CertificateRequest') to establish a mutual TLS connection between client and mitmproxy (combined with 'client_certs' option for mitmproxy and upstream).", nil},
		{"ciphers_client", options.TypeOptStr, nil, "Set supported ciphers for client <-> mitmproxy connections using OpenSSL syntax.", nil},
		{"ciphers_server", options.TypeOptStr, nil, "Set supported ciphers for mitmproxy <-> server connections using OpenSSL syntax.", nil},
	} {
		if err := l.AddOption(ctx, o.name, o.typ, o.def, o.help, o.choices...); err != nil {
			return err
		}
	}
	return nil
}

// Configure validates and applies the TLS options
// (py:mitmproxy/addons/tlsconfig.py:471-539). The user-configured
// certificates are loaded into the store; an invalid certs entry, ECDH curve
// name or cipher suite name rejects the change with an *options.OptionsError.
func (t *TLSConfig) Configure(ctx context.Context, updated map[string]struct{}) error {
	if updatedAny(updated, "certs", "confdir", "key_size", "cert_passphrase") {
		var passphrase []byte
		if p := t.options.OptStr("cert_passphrase"); p != nil {
			passphrase = []byte(*p)
		}
		store, err := certs.FromStore(expandUser(t.options.Str("confdir")), options.ConfBasename, t.options.Int("key_size"), passphrase)
		if err != nil {
			return &options.OptionsError{Msg: err.Error(), Err: err}
		}
		if store.DefaultCA().HasExpired() {
			slog.WarnContext(ctx, "The mitmproxy certificate authority has expired!\nPlease delete all CA-related files in your ~/.mitmproxy folder.\nThe CA will be regenerated automatically after restarting mitmproxy.\nSee https://docs.mitmproxy.org/stable/concepts-certificates/ for additional help.")
		}
		for _, spec := range t.options.Seq("certs") {
			if err := store.AddCertSpec(spec, passphrase); err != nil {
				return &options.OptionsError{Msg: err.Error(), Err: err}
			}
		}
		t.store = store
	}

	if updatedAny(updated, "tls_ecdh_curve_client", "tls_ecdh_curve_server") {
		for _, name := range []string{"tls_ecdh_curve_client", "tls_ecdh_curve_server"} {
			if curve := t.options.OptStr(name); curve != nil {
				if _, ok := ecCurves[*curve]; !ok {
					return options.Errorf("Invalid ECDH curve: %q. Valid curves are: %s", *curve, strings.Join(ecCurveNames, ", "))
				}
			}
		}
	}

	for _, o := range []struct {
		name        string
		warnUnbound bool
	}{
		{"tls_version_client_min", true},
		{"tls_version_client_max", false},
		{"tls_version_server_min", true},
		{"tls_version_server_max", false},
	} {
		if updatedAny(updated, o.name) {
			t.warnUnsupportedVersion(ctx, o.name, o.warnUnbound)
		}
	}

	for _, name := range []string{"ciphers_client", "ciphers_server"} {
		if updatedAny(updated, name) {
			if value := t.options.OptStr(name); value != nil {
				if _, err := parseCipherOption(name, *value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Running initializes the certificate store before serving connections.
func (t *TLSConfig) Running(ctx context.Context) error {
	return t.Configure(ctx, map[string]struct{}{"confdir": {}})
}

// Done closes the key log after connections stop, returning any close error.
// Repeated calls do nothing; the closed writer is never reopened.
func (t *TLSConfig) Done(context.Context) error {
	if t.keyLogWriter == nil {
		return nil
	}
	err := t.keyLogWriter.Close()
	t.keyLogWriter = nil
	return err
}

// warnUnsupportedVersion logs when a tls_version_* option names a TLS version
// crypto/tls cannot negotiate (py:mitmproxy/addons/tlsconfig.py:541-558;
// the message names crypto/tls instead of an OpenSSL build, docs/compat.md).
func (t *TLSConfig) warnUnsupportedVersion(ctx context.Context, option string, warnUnbound bool) {
	value := t.options.Str(option)
	supported := strings.Join(supportedTLSVersionNames, ", ")
	switch {
	case value == "UNBOUNDED":
		if warnUnbound {
			slog.InfoContext(ctx, fmt.Sprintf("%s has been set to UNBOUNDED. Note that crypto/tls only supports the following TLS versions: %s", option, supported))
		}
	case tlsVersionIDs[value] == 0:
		slog.WarnContext(ctx, fmt.Sprintf("%s has been set to %s, which is not supported by crypto/tls. crypto/tls only supports the following versions: %s", option, value, supported))
	}
}

// TLSClientHello decides whether the server handshake must complete before
// the client handshake, so the upstream certificate can shape the leaf the
// proxy presents (py:mitmproxy/addons/tlsconfig.py:204-208).
func (t *TLSConfig) TLSClientHello(ctx context.Context, d *hookdata.ClientHello) error {
	// connection_strategy is registered by the proxy server addon; its
	// upstream default is "eager".
	strategy := "eager"
	if t.options.Has("connection_strategy") {
		strategy = t.options.Str("connection_strategy")
	}
	d.EstablishServerTLSFirst = d.Context.Server.TLS && strategy == "eager"
	return nil
}

// TLSStartClient builds the configuration for TLS between the client and the
// proxy (py:mitmproxy/addons/tlsconfig.py:210-271). It returns early when a
// user addon already provided one. The chosen leaf certificate is published
// as the client connection's MitmCert; the TLS layer replaces it only when a
// handshake certificate is present.
func (t *TLSConfig) TLSStartClient(ctx context.Context, d *hookdata.TLS) error {
	if d.IsDTLS {
		return t.dtlsStartClient(ctx, d)
	}
	if d.Config != nil {
		return nil
	}
	client := d.Context.Client
	server := d.Context.Server

	entry, err := t.getCert(d.Context)
	if err != nil {
		return err
	}

	if len(client.CipherList) == 0 {
		if ciphers := t.options.OptStr("ciphers_client"); ciphers != nil {
			client.CipherList = strings.Split(*ciphers, ":")
		}
	}

	cfg := &tls.Config{
		MinVersion:       minTLSVersion(t.options.Str("tls_version_client_min")),
		MaxVersion:       maxTLSVersion(t.options.Str("tls_version_client_max")),
		CurvePreferences: curvePreferences(t.options.OptStr("tls_ecdh_curve_client")),
		KeyLogWriter:     t.keyLog(),
	}
	// Without a cipher list the crypto/tls defaults apply, where upstream
	// would install its own OpenSSL default cipher string (docs/compat.md).
	if len(client.CipherList) > 0 {
		ids, err := suiteIDs("ciphers_client", client.CipherList)
		if err != nil {
			return err
		}
		cfg.CipherSuites = ids
	}
	if t.options.Bool("request_client_cert") {
		cfg.ClientAuth = tls.RequestClientCert
	}

	// The handshake sends the chosen leaf, then the entry's chain beyond
	// its own first certificate, exactly as upstream's use_certificate
	// replaces the first certificate loaded from the chain file, and then
	// the upstream server's certificates when
	// add_upstream_certs_to_client_chain is set.
	certificate := tls.Certificate{
		Certificate: [][]byte{entry.Cert.X509().Raw},
		PrivateKey:  entry.PrivateKey,
		Leaf:        entry.Cert.X509(),
	}
	if len(entry.ChainCerts) > 1 {
		for _, chain := range entry.ChainCerts[1:] {
			certificate.Certificate = append(certificate.Certificate, chain.X509().Raw)
		}
	}
	if t.options.Bool("add_upstream_certs_to_client_chain") {
		for _, pemCert := range server.CertificateList {
			extra, err := certs.ParseCert(pemCert)
			if err != nil {
				return fmt.Errorf("tlsconfig: upstream certificate: %w", err)
			}
			certificate.Certificate = append(certificate.Certificate, extra.X509().Raw)
		}
	}
	cfg.Certificates = []tls.Certificate{certificate}

	// Force HTTP/1 for the outer TLS session of secure web proxies:
	// CONNECT over HTTP/2 is not supported, as it is not by upstream.
	// The HTTP child may already be in the stack; a later client TLS layer
	// denotes the tunneled session, which may negotiate HTTP/2 normally.
	clientALPN := client.ALPN
	clientTLSIndex := -1
	for i, item := range d.Context.Layers {
		if l, ok := item.(interface{ Kind() hookdata.LayerKind }); ok && l.Kind() == hookdata.LayerClientTLS {
			clientTLSIndex = i
		}
	}
	if clientTLSIndex == 1 {
		if top, ok := d.Context.Layers[0].(interface{ Kind() hookdata.LayerKind }); ok && top.Kind() == hookdata.LayerRegular {
			clientALPN = []byte("http/1.1")
		}
	}
	// The configuration carries exactly one selected protocol, or none.
	if proto := alpnSelect(clientALPN, server.ALPN, client.ALPNOffers, t.options.Bool("http2")); proto != nil {
		cfg.NextProtos = []string{string(proto)}
	}

	client.MitmCert = entry.Cert.PEM()
	d.Config = cfg
	return nil
}

// TLSStartServer builds the configuration for TLS between the proxy and the
// server (py:mitmproxy/addons/tlsconfig.py:273-377). It returns early when a
// user addon already provided one.
func (t *TLSConfig) TLSStartServer(ctx context.Context, d *hookdata.TLS) error {
	if d.IsDTLS {
		return t.dtlsStartServer(ctx, d)
	}
	if d.Config != nil {
		return nil
	}
	client := d.Context.Client
	server := d.Context.Server
	if server.Address == nil {
		return fmt.Errorf("tlsconfig: starting server TLS without a server address")
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

	cfg := &tls.Config{
		MinVersion:       minTLSVersion(t.options.Str("tls_version_server_min")),
		MaxVersion:       maxTLSVersion(t.options.Str("tls_version_server_max")),
		CurvePreferences: curvePreferences(t.options.OptStr("tls_ecdh_curve_server")),
		KeyLogWriter:     t.keyLog(),
	}

	if len(server.CipherList) == 0 {
		if ciphers := t.options.OptStr("ciphers_server"); ciphers != nil {
			server.CipherList = strings.Split(*ciphers, ":")
		}
	}
	if len(server.CipherList) > 0 {
		ids, err := suiteIDs("ciphers_server", server.CipherList)
		if err != nil {
			return err
		}
		cfg.CipherSuites = ids
	}

	if path := t.options.OptStr("client_certs"); path != nil {
		cert, err := clientCertificate(expandUser(*path), server)
		if err != nil {
			return err
		}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
	}

	if t.options.Bool("ssl_insecure") {
		cfg.InsecureSkipVerify = true
	} else {
		pool, err := trustedRoots(t.options.OptStr("ssl_verify_upstream_trusted_ca"), t.options.OptStr("ssl_verify_upstream_trusted_confdir"))
		if err != nil {
			return err
		}
		cfg.RootCAs = pool
		if *server.SNI == "" {
			return fmt.Errorf("Cannot validate certificate hostname without SNI") //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
	}

	if sni := *server.SNI; sni != "" {
		if _, err := netip.ParseAddr(sni); err == nil {
			// crypto/tls never sends an IP literal in the server_name
			// extension (RFC 6066) and verifies it against the IP SANs.
			cfg.ServerName = sni
		} else {
			name, err := encodeIDNA(sni)
			if err != nil {
				return fmt.Errorf("tlsconfig: server name %q: %w", sni, err)
			}
			cfg.ServerName = name
		}
	}

	for _, offer := range server.ALPNOffers {
		cfg.NextProtos = append(cfg.NextProtos, string(offer))
	}

	d.Config = cfg
	return nil
}

// clientCertificate loads the client certificate for a server connection:
// path itself when it is a file, or <path>/<server name>.pem when path is a
// directory (py:mitmproxy/addons/tlsconfig.py:319-328). The server name may
// come from the client's SNI, so only a file directly inside the directory
// is a candidate; any other name is treated as a missing file.
func clientCertificate(path string, server *connection.Server) (*tls.Certificate, error) {
	name := path
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		serverName := server.Address.Host
		if server.SNI != nil && *server.SNI != "" {
			serverName = *server.SNI
		}
		file := serverName + ".pem"
		if !filepath.IsLocal(file) || filepath.Base(file) != file || strings.ContainsRune(file, 0) {
			return nil, nil
		}
		name = filepath.Join(path, file)
		if _, err := os.Stat(name); err != nil {
			return nil, nil
		}
	}
	cert, err := tls.LoadX509KeyPair(name, name)
	if err != nil {
		return nil, fmt.Errorf("tlsconfig: client certificate %s: %w", name, err)
	}
	return &cert, nil
}

// Request answers a request for the certificate revocation list of the
// proxy's CA: a live request without a response or an error, whose path ends
// in the CA's CRL path, receives the store's CRL
// (py:mitmproxy/addons/tlsconfig.py:635-644). The response is built under
// the dispatch lock; it is small and involves no I/O.
func (t *TLSConfig) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if !f.Live || f.Error != nil || f.Response != nil || f.Request == nil || t.store == nil {
		return nil
	}
	// Check whether the request carries the magic CRL token at the end.
	if !strings.HasSuffix(f.Request.Path, t.crlPath()) {
		return nil
	}
	response, err := httpmsg.MakeResponse(http.StatusOK, t.store.DefaultCRL(), httpmsg.Headers{{Name: []byte("Content-Type"), Value: []byte("application/pkix-crl")}})
	if err != nil {
		return err
	}
	f.Response = response
	return nil
}

// keyLog returns the writer for TLS master secrets when the SSLKEYLOGFILE
// environment variable names a file, opening it on first use
// (py:mitmproxy/net/tls.py MasterSecretLogger).
func (t *TLSConfig) keyLog() io.Writer {
	t.keyLogOnce.Do(func() {
		path := os.Getenv("SSLKEYLOGFILE")
		if path == "" {
			return
		}
		f, err := os.OpenFile(expandUser(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			slog.Warn(fmt.Sprintf("tlsconfig: cannot open SSLKEYLOGFILE: %v", err))
			return
		}
		t.keyLogWriter = f
	})
	return t.keyLogWriter
}

// updatedAny reports whether any of the names is in the updated set of a
// configure hook.
func updatedAny(updated map[string]struct{}, names ...string) bool {
	for _, name := range names {
		if _, ok := updated[name]; ok {
			return true
		}
	}
	return false
}

// expandUser is Python's os.path.expanduser for a leading "~": the home
// directory of the current user. Any other path is returned unchanged.
func expandUser(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + path[1:]
		}
	}
	return path
}
