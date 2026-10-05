// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package connection describes the client and server connections of a flow.
//
// The types expose metadata about a connection only, never the socket
// itself: all I/O is handled by the proxy server. Their serialised state
// matches mitmproxy's flow format 21 key for key.
package connection

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
)

// State is the state of the underlying socket, as a set of flags.
type State uint8

// Connection states. Open is CanRead|CanWrite.
const (
	Closed   State = 0
	CanRead  State = 1
	CanWrite State = 2
	Open           = CanRead | CanWrite
)

// String returns the upstream flag name, for example "OPEN" or "CAN_READ".
func (s State) String() string {
	switch s {
	case Closed:
		return "CLOSED"
	case CanRead:
		return "CAN_READ"
	case CanWrite:
		return "CAN_WRITE"
	case Open:
		return "OPEN"
	}
	return "State(" + strconv.Itoa(int(s)) + ")"
}

// TransportProtocol is the transport a connection uses.
type TransportProtocol string

// Transport protocols.
const (
	TCP TransportProtocol = "tcp"
	UDP TransportProtocol = "udp"
)

// TLSVersion is a negotiated TLS version, named as OpenSSL's SSL_get_version
// names it. The empty string means no TLS version is known.
type TLSVersion string

// TLS versions upstream accepts in serialised state.
const (
	SSLv3    TLSVersion = "SSLv3"
	TLSv1    TLSVersion = "TLSv1"
	TLSv1_1  TLSVersion = "TLSv1.1"
	TLSv1_2  TLSVersion = "TLSv1.2"
	TLSv1_3  TLSVersion = "TLSv1.3"
	DTLSv0_9 TLSVersion = "DTLSv0.9"
	DTLSv1   TLSVersion = "DTLSv1"
	DTLSv1_2 TLSVersion = "DTLSv1.2"
	QUICv1   TLSVersion = "QUICv1"
)

var tlsVersions = []TLSVersion{SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3, DTLSv0_9, DTLSv1, DTLSv1_2, QUICv1}

// IPv6Scope holds the extra fields of an IPv6 socket address, which Python
// reports as a (host, port, flowinfo, scope_id) 4-tuple.
type IPv6Scope struct {
	FlowInfo uint32
	ScopeID  uint32
}

// Address is a (host, port) socket address. Host is an IP address or, for
// a server's target address, a domain name.
type Address struct {
	Host string
	Port int
	// Scope is set when the address came from an IPv6 socket that reported
	// a 4-tuple. It is kept so that the address serialises unchanged.
	Scope *IPv6Scope
}

// String formats a like upstream's human.format_address: IPv6 hosts are
// bracketed, IPv4-mapped IPv6 hosts print as IPv4, and an unspecified host
// prints as "*".
func (a Address) String() string {
	return human.FormatAddress(a.Host, a.Port)
}

func formatAddress(a *Address) string {
	if a == nil {
		return "<no address>"
	}
	return a.String()
}

// state returns the address as a state tuple.
func (a Address) state() []any {
	if a.Scope != nil {
		return []any{a.Host, int64(a.Port), int64(a.Scope.FlowInfo), int64(a.Scope.ScopeID)}
	}
	return []any{a.Host, int64(a.Port)}
}

func optAddressState(a *Address) any {
	if a == nil {
		return nil
	}
	return a.state()
}

// socketAddress parses a peername or sockname tuple. Like upstream, it
// accepts both (host, port) and the IPv6 (host, port, flowinfo, scope_id).
func socketAddress(v any) (Address, error) {
	l, err := state.AsList(v)
	if err != nil {
		return Address{}, err
	}
	switch len(l) {
	case 2:
		return address(l)
	case 4:
		a, err := address(l[:2])
		if err != nil {
			return Address{}, err
		}
		fi, err := state.AsInt(l[2])
		if err != nil {
			return Address{}, err
		}
		sid, err := state.AsInt(l[3])
		if err != nil {
			return Address{}, err
		}
		a.Scope = &IPv6Scope{FlowInfo: uint32(fi), ScopeID: uint32(sid)}
		return a, nil
	}
	return Address{}, fmt.Errorf("expected a (host, port) tuple, got %d items", len(l))
}

// address parses a strict (host, port) tuple.
func address(v any) (Address, error) {
	l, err := state.Tuple(v, 2)
	if err != nil {
		return Address{}, err
	}
	host, err := state.AsString(l[0])
	if err != nil {
		return Address{}, err
	}
	port, err := state.AsInt(l[1])
	if err != nil {
		return Address{}, err
	}
	return Address{Host: host, Port: int(port)}, nil
}

// Connection holds the fields client and server connections share.
type Connection struct {
	// Peername is the remote's address.
	Peername *Address
	// Sockname is our local address.
	Sockname *Address
	// State is the current socket state. It is not serialised.
	State State
	// ID uniquely identifies the connection, also across recorded flows.
	ID string
	// TransportProtocol is the transport in use.
	TransportProtocol TransportProtocol
	// Error describes a general error with connections to this address.
	// It signals that new connections to the endpoint should not be
	// attempted, for example because of an untrusted certificate. Nil means
	// no error.
	Error *string
	// TLS reports whether TLS should eventually be established. Use
	// [Connection.TLSEstablished] to check whether it has been.
	TLS bool
	// CertificateList is the certificate chain sent by the peer, PEM encoded,
	// end-entity certificate first.
	CertificateList [][]byte
	// ALPN is the negotiated application protocol. Nil means none.
	ALPN []byte
	// ALPNOffers are the protocols offered in the ClientHello.
	ALPNOffers [][]byte
	// Cipher is the active cipher name as OpenSSL reports it. Nil means none.
	Cipher *string
	// CipherList holds the ciphers the proxy accepts on this connection.
	CipherList []string
	// TLSVersion is the active TLS version, or empty when unknown.
	TLSVersion TLSVersion
	// SNI is the Server Name Indication from the ClientHello. Nil means none.
	SNI *string
	// TimestampStart is when the connection started. Clients always have it.
	TimestampStart *float64
	// TimestampEnd is when the connection was closed.
	TimestampEnd *float64
	// TimestampTLSSetup is when the TLS handshake completed.
	TimestampTLSSetup *float64
}

// Connected reports whether the connection is open in both directions.
func (c *Connection) Connected() bool {
	return c.State == Open
}

// TLSEstablished reports whether the TLS handshake has completed.
func (c *Connection) TLSEstablished() bool {
	return c.TimestampTLSSetup != nil
}

// tlsState returns the TLS suffix of String.
func (c *Connection) tlsState() string {
	switch {
	case len(c.ALPN) > 0:
		return ", alpn=" + strings.ToValidUTF8(string(c.ALPN), "�")
	case c.TLSEstablished():
		return ", tls"
	}
	return ""
}

// putState writes the shared fields in upstream's order, from peername to
// timestamp_tls_setup.
func (c *Connection) putState(m *state.Map) {
	m.Set("peername", optAddressState(c.Peername))
	m.Set("sockname", optAddressState(c.Sockname))
	m.Set("id", c.ID)
	m.Set("transport_protocol", string(c.TransportProtocol))
	m.Set("error", stateutil.Opt(c.Error))
	m.Set("tls", c.TLS)
	m.Set("certificate_list", stateutil.BytesList(c.CertificateList))
	m.Set("alpn", stateutil.OptBytes(c.ALPN))
	m.Set("alpn_offers", stateutil.BytesList(c.ALPNOffers))
	m.Set("cipher", stateutil.Opt(c.Cipher))
	cipherList := make([]any, len(c.CipherList))
	for i, name := range c.CipherList {
		cipherList[i] = name
	}
	m.Set("cipher_list", cipherList)
	if c.TLSVersion == "" {
		m.Set("tls_version", nil)
	} else {
		m.Set("tls_version", string(c.TLSVersion))
	}
	m.Set("sni", stateutil.Opt(c.SNI))
	m.Set("timestamp_start", stateutil.Opt(c.TimestampStart))
	m.Set("timestamp_end", stateutil.Opt(c.TimestampEnd))
	m.Set("timestamp_tls_setup", stateutil.Opt(c.TimestampTLSSetup))
}

// readState reads the shared fields into c. The State field is kept.
func (c *Connection) readState(d *state.Decoder) {
	if v := d.Any("peername"); v != nil {
		c.Peername = decodeAddress(d, "peername", v, socketAddress)
	} else {
		c.Peername = nil
	}
	if v := d.Any("sockname"); v != nil {
		c.Sockname = decodeAddress(d, "sockname", v, socketAddress)
	} else {
		c.Sockname = nil
	}
	c.ID = d.String("id")
	tp := TransportProtocol(d.String("transport_protocol"))
	if d.Err() == nil && tp != TCP && tp != UDP {
		d.Fail(fmt.Errorf("invalid value for transport_protocol: %q does not match any literal value", tp))
	}
	c.TransportProtocol = tp
	c.Error = d.OptString("error")
	c.TLS = d.Bool("tls")
	c.CertificateList = decodeList(d, "certificate_list", state.AsBytes)
	c.ALPN = d.OptBytes("alpn")
	c.ALPNOffers = decodeList(d, "alpn_offers", state.AsBytes)
	c.Cipher = d.OptString("cipher")
	c.CipherList = decodeList(d, "cipher_list", state.AsString)
	c.TLSVersion = ""
	if v := d.OptString("tls_version"); v != nil {
		if !slices.Contains(tlsVersions, TLSVersion(*v)) {
			d.Fail(fmt.Errorf("invalid value for tls_version: %q does not match any literal value", *v))
		}
		c.TLSVersion = TLSVersion(*v)
	}
	c.SNI = d.OptString("sni")
	c.TimestampStart = d.OptFloat("timestamp_start")
	c.TimestampEnd = d.OptFloat("timestamp_end")
	c.TimestampTLSSetup = d.OptFloat("timestamp_tls_setup")
}

func decodeAddress(d *state.Decoder, key string, v any, f func(any) (Address, error)) *Address {
	a, err := f(v)
	if err != nil {
		d.Fail(fmt.Errorf("field %q: %w", key, err))
		return nil
	}
	return &a
}

func decodeList[T any](d *state.Decoder, key string, f func(any) (T, error)) []T {
	v := d.Any(key)
	if d.Err() != nil {
		return nil
	}
	l, err := state.ListOf(v, f)
	if err != nil {
		d.Fail(fmt.Errorf("field %q: %w", key, err))
	}
	return l
}

func (c *Connection) clone() Connection {
	out := *c
	out.Peername = cloneAddress(c.Peername)
	out.Sockname = cloneAddress(c.Sockname)
	out.Error = clonePtr(c.Error)
	out.CertificateList = cloneBytesList(c.CertificateList)
	out.ALPN = slices.Clone(c.ALPN)
	out.ALPNOffers = cloneBytesList(c.ALPNOffers)
	out.Cipher = clonePtr(c.Cipher)
	out.CipherList = slices.Clone(c.CipherList)
	out.SNI = clonePtr(c.SNI)
	out.TimestampStart = clonePtr(c.TimestampStart)
	out.TimestampEnd = clonePtr(c.TimestampEnd)
	out.TimestampTLSSetup = clonePtr(c.TimestampTLSSetup)
	return out
}

func cloneAddress(a *Address) *Address {
	if a == nil {
		return nil
	}
	out := *a
	out.Scope = clonePtr(a.Scope)
	return &out
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneBytesList(bs [][]byte) [][]byte {
	if bs == nil {
		return nil
	}
	out := make([][]byte, len(bs))
	for i, b := range bs {
		out[i] = slices.Clone(b)
	}
	return out
}

// Client is a connection between a client and the proxy.
type Client struct {
	Connection
	// MitmCert is the PEM-encoded certificate the proxy presented to the
	// client. Nil means none.
	MitmCert []byte
	// ProxyMode is the full spec of the proxy mode the client connected to,
	// for example "regular" or "reverse:https://example.com".
	ProxyMode string
}

// NewClient returns a closed TCP client connection with a fresh ID, in
// regular proxy mode, started at timestampStart.
func NewClient(peername, sockname Address, timestampStart float64) *Client {
	return &Client{
		Peername:          &peername,
		Sockname:          &sockname,
		ID:                stateutil.NewID(),
		TransportProtocol: TCP,
		TimestampStart:    &timestampStart,
		ProxyMode:         "regular",
	}
}

// String formats c like upstream, for example
// "Client(127.0.0.1:52314, state=closed, alpn=foo)".
func (c *Client) String() string {
	return "Client(" + formatAddress(c.Peername) + ", state=" + strings.ToLower(c.State.String()) + c.tlsState() + ")"
}

// GetState returns c's serialised state.
func (c *Client) GetState() *state.Map {
	m := state.NewMap(19)
	c.putState(m)
	m.Set("mitmcert", stateutil.OptBytes(c.MitmCert))
	m.Set("proxy_mode", c.ProxyMode)
	return m
}

// SetState replaces c's fields with those in m, consuming m. On error c is
// left unchanged.
func (c *Client) SetState(m *state.Map) error {
	d := state.NewDecoder(m, "Client")
	n := Client{State: c.State}
	n.readState(d)
	n.MitmCert = d.OptBytes("mitmcert")
	n.ProxyMode = d.String("proxy_mode")
	if d.Err() == nil {
		// Upstream's Client declares these attributes without "| None".
		switch {
		case n.Peername == nil:
			d.Fail(errors.New("attribute peername must not be None"))
		case n.Sockname == nil:
			d.Fail(errors.New("attribute sockname must not be None"))
		case n.TimestampStart == nil:
			d.Fail(errors.New("attribute timestamp_start must not be None"))
		}
	}
	if err := d.Finish(); err != nil {
		return err
	}
	*c = n
	return nil
}

// ClientFromState returns a new Client built from m, consuming m.
func ClientFromState(m *state.Map) (*Client, error) {
	c := &Client{}
	if err := c.SetState(m); err != nil {
		return nil, err
	}
	return c, nil
}

// Clone returns a deep copy of c with the same ID.
func (c *Client) Clone() *Client {
	out := *c
	out.Connection = c.clone()
	out.MitmCert = slices.Clone(c.MitmCert)
	return &out
}

// ServerSpec names an upstream proxy or server: a scheme such as "http",
// "https", "tls", "dns" or "quic" and its address.
type ServerSpec struct {
	Scheme  string
	Address Address
}

func (s *ServerSpec) state() any {
	if s == nil {
		return nil
	}
	return []any{s.Scheme, s.Address.state()}
}

func serverSpec(v any) (*ServerSpec, error) {
	l, err := state.Tuple(v, 2)
	if err != nil {
		return nil, err
	}
	scheme, err := state.AsString(l[0])
	if err != nil {
		return nil, err
	}
	a, err := address(l[1])
	if err != nil {
		return nil, err
	}
	return &ServerSpec{Scheme: scheme, Address: a}, nil
}

// Server is a connection between the proxy and an upstream server.
type Server struct {
	Connection
	// Address is the server's (host, port) target. Host is a domain or an
	// IP address, depending on the proxy mode and the client. Nil means
	// unknown.
	Address *Address
	// TimestampTCPSetup is when the TCP handshake completed.
	TimestampTCPSetup *float64
	// Via is an optional proxy through which the connection is established.
	Via *ServerSpec
}

// NewServer returns a closed TCP server connection to address with a fresh
// ID. A nil address means the target is not known yet.
func NewServer(address *Address) *Server {
	return &Server{
		ID:                stateutil.NewID(),
		TransportProtocol: TCP,
		Address:           cloneAddress(address),
	}
}

// String formats s like upstream, for example
// "Server(example.com:443, state=closed, alpn=h2, src_port=54321)".
func (s *Server) String() string {
	localPort := ""
	if s.Sockname != nil {
		localPort = ", src_port=" + strconv.Itoa(s.Sockname.Port)
	}
	return "Server(" + formatAddress(s.Address) + ", state=" + strings.ToLower(s.State.String()) + s.tlsState() + localPort + ")"
}

// GetState returns s's serialised state.
func (s *Server) GetState() *state.Map {
	m := state.NewMap(20)
	s.putState(m)
	m.Set("address", optAddressState(s.Address))
	m.Set("timestamp_tcp_setup", stateutil.Opt(s.TimestampTCPSetup))
	m.Set("via", s.Via.state())
	return m
}

// SetState replaces s's fields with those in m, consuming m. On error s is
// left unchanged.
func (s *Server) SetState(m *state.Map) error {
	d := state.NewDecoder(m, "Server")
	n := Server{State: s.State}
	n.readState(d)
	if v := d.Any("address"); v != nil {
		n.Address = decodeAddress(d, "address", v, address)
	}
	n.TimestampTCPSetup = d.OptFloat("timestamp_tcp_setup")
	if v := d.Any("via"); v != nil {
		via, err := serverSpec(v)
		if err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "via", err))
		}
		n.Via = via
	}
	if err := d.Finish(); err != nil {
		return err
	}
	*s = n
	return nil
}

// ServerFromState returns a new Server built from m, consuming m.
func ServerFromState(m *state.Map) (*Server, error) {
	s := &Server{}
	if err := s.SetState(m); err != nil {
		return nil, err
	}
	return s, nil
}

// Clone returns a deep copy of s with the same ID.
func (s *Server) Clone() *Server {
	out := *s
	out.Connection = s.clone()
	out.Address = cloneAddress(s.Address)
	out.TimestampTCPSetup = clonePtr(s.TimestampTCPSetup)
	if s.Via != nil {
		via := *s.Via
		via.Address.Scope = clonePtr(s.Via.Address.Scope)
		out.Via = &via
	}
	return &out
}
