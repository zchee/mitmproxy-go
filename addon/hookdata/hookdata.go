// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package hookdata defines the values the proxy passes to the connection,
// TLS and QUIC hooks, mirroring the dataclasses mitmproxy passes to the
// same hooks.
//
// The proxy creates these values and fills them; an addon reads them and
// sets the fields documented as set by a handler. Each type keeps exactly
// the fields its mitmproxy counterpart exposes to addons.
package hookdata

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"strconv"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/options"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

// Context is the context of one proxied connection, shared by the protocol
// layers that handle it (py:mitmproxy/proxy/context.py Context).
type Context struct {
	// Client is the client connection.
	Client *connection.Client
	// Server is the server connection. It is always set, even before there
	// is a server connection; its Address is nil until one is chosen.
	Server *connection.Server
	// Options gives the protocol layers access to the options. Addons
	// should use the options they were loaded with instead.
	Options *options.Manager
	// Layers is the protocol layer stack, outermost first.
	Layers []any
}

// NextLayer is the value of the next_layer hook, which decides the protocol
// layer that handles a connection next (py:mitmproxy/proxy/layer.py
// NextLayer).
type NextLayer struct {
	// Context is the context of the connection.
	Context *Context
	// DataClient is the data received from the client so far.
	DataClient []byte
	// DataServer is the data received from the server so far.
	DataServer []byte
	// Layer is the stack of layers to use next, outermost first. A handler
	// sets it; nil leaves the decision to the handlers after it, or to a
	// later call of the hook when more data has arrived.
	Layer LayerStack
}

// ServerConnection is the value of the server_connect, server_connected,
// server_disconnected and server_connect_error hooks
// (py:mitmproxy/proxy/server_hooks.py ServerConnectionHookData).
type ServerConnection struct {
	// Server is the server connection the hook is about.
	Server *connection.Server
	// Client is the client on the other end.
	Client *connection.Client
}

// Socks5Auth is the value of the socks5_auth hook, which checks the
// credentials a SOCKS5 client sent (py:mitmproxy/proxy/layers/modes.py
// Socks5AuthData).
type Socks5Auth struct {
	// Client is the client connection.
	Client *connection.Client
	// Username is the user name the client sent.
	Username string
	// Password is the password the client sent.
	Password string
	// Valid reports whether the credentials are accepted. A handler sets
	// it; it starts out false.
	Valid bool
}

// ClientHello is the value of the tls_clienthello hook, which runs when a
// client's TLS ClientHello has been received (py:mitmproxy/tls.py
// ClientHelloData).
type ClientHello struct {
	// Context is the context of the connection.
	Context *Context
	// ClientHello is the parsed hello received from the client.
	ClientHello *tlsparse.ClientHello
	// IgnoreConnection, when a handler sets it, forwards the connection's
	// encrypted contents unmodified instead of intercepting them.
	IgnoreConnection bool
	// EstablishServerTLSFirst, when a handler sets it, pauses the client
	// handshake until TLS with the upstream server is established, so the
	// server certificate can be used when generating the interception
	// certificate.
	EstablishServerTLSFirst bool
}

// TLS is the value of the tls_start_client, tls_start_server,
// tls_established_client, tls_established_server, tls_failed_client and
// tls_failed_server hooks (py:mitmproxy/tls.py TlsData).
type TLS struct {
	// Conn is the connection the hook is about: the Connection embedded in
	// Context.Client or in Context.Server. [TLS.IsClient] and
	// [TLS.IsServer] tell which side it is.
	Conn *connection.Connection
	// Context is the context of the connection.
	Context *Context
	// Config is the TLS configuration for the connection. A tls_start_*
	// handler sets it; it is the counterpart of mitmproxy's ssl_conn.
	Config *tls.Config
	// IsDTLS reports whether the connection uses DTLS.
	IsDTLS bool
}

// QUICTLS is the value of the quic_start_client and quic_start_server
// hooks (py:mitmproxy/proxy/layers/quic/_hooks.py QuicTlsData).
type QUICTLS struct {
	// Conn is the connection the hook is about: the Connection embedded in
	// Context.Client or in Context.Server. [QUICTLS.IsClient] and
	// [QUICTLS.IsServer] tell which side it is.
	Conn *connection.Connection
	// Context is the context of the connection.
	Context *Context
	// IsDTLS is part of the TLS hook value this one extends; QUIC
	// connections leave it false.
	IsDTLS bool
	// Settings is the TLS configuration for the QUIC connection. A
	// quic_start_* handler sets it.
	Settings *QUICTLSSettings
}

// IsClient reports whether the hook is about the client connection, the
// equivalent of mitmproxy's isinstance(data.conn, Client) or
// data.conn == data.context.client.
func (d *TLS) IsClient() bool { return isClient(d.Conn, d.Context) }

// IsServer reports whether the hook is about the server connection, the
// equivalent of mitmproxy's isinstance(data.conn, Server) or
// data.conn == data.context.server.
func (d *TLS) IsServer() bool { return isServer(d.Conn, d.Context) }

// IsClient reports whether the hook is about the client connection, the
// equivalent of mitmproxy's isinstance(data.conn, Client) or
// data.conn == data.context.client.
func (d *QUICTLS) IsClient() bool { return isClient(d.Conn, d.Context) }

// IsServer reports whether the hook is about the server connection, the
// equivalent of mitmproxy's isinstance(data.conn, Server) or
// data.conn == data.context.server.
func (d *QUICTLS) IsServer() bool { return isServer(d.Conn, d.Context) }

func isClient(conn *connection.Connection, ctx *Context) bool {
	return conn != nil && ctx != nil && ctx.Client != nil && conn == &ctx.Client.Connection
}

func isServer(conn *connection.Connection, ctx *Context) bool {
	return conn != nil && ctx != nil && ctx.Server != nil && conn == &ctx.Server.Connection
}

// VerifyMode says whether and how a peer's certificate is verified
// (Python's ssl.VerifyMode).
type VerifyMode int

// The verification modes.
const (
	// VerifyNone does not verify the peer certificate.
	VerifyNone VerifyMode = iota
	// VerifyOptional verifies the peer certificate when the peer sends one.
	VerifyOptional
	// VerifyRequired requires a valid peer certificate.
	VerifyRequired
)

// String returns the name of the mode as Python's ssl module spells it.
func (m VerifyMode) String() string {
	switch m {
	case VerifyNone:
		return "CERT_NONE"
	case VerifyOptional:
		return "CERT_OPTIONAL"
	case VerifyRequired:
		return "CERT_REQUIRED"
	default:
		return "VerifyMode(" + strconv.Itoa(int(m)) + ")"
	}
}

// QUICTLSSettings is the TLS configuration of a QUIC connection
// (py:mitmproxy/proxy/layers/quic/_hooks.py QuicTlsSettings). A nil field
// leaves the setting at the QUIC stack's default.
type QUICTLSSettings struct {
	// ALPNProtocols lists the supported ALPN protocols.
	ALPNProtocols []string
	// Certificate is the certificate to present.
	Certificate *x509.Certificate
	// CertificateChain lists additional certificates to send to the peer.
	CertificateChain []*x509.Certificate
	// CertificatePrivateKey is the private key of Certificate.
	CertificatePrivateKey crypto.PrivateKey
	// CipherSuites lists the allowed or advertised cipher suites, as
	// crypto/tls cipher suite IDs.
	CipherSuites []uint16
	// CAPath names a directory holding the certificates to verify the peer
	// with.
	CAPath *string
	// CAFile names a PEM file holding the certificates to verify the peer
	// with.
	CAFile *string
	// VerifyMode says whether and how the peer certificate is verified.
	VerifyMode *VerifyMode
}
