// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package tlsparse reads the TLS ClientHello a client sends first: it finds
// the handshake message in the TLS records the proxy has received so far,
// which may spread it over several records, and parses the parts that
// mitmproxy reports to addons (py:mitmproxy/tls.py ClientHello,
// py:mitmproxy/proxy/layers/tls.py and the kaitai-generated parser in
// py:mitmproxy/contrib/kaitaistruct/tls_client_hello.py).
//
// The parser follows mitmproxy's decoding rules, including its permissive
// length handling; intentional differences are listed in docs/compat.md.
// No length read from the input is trusted before its bytes are available.
package tlsparse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/zchee/mitmproxy-go/internal/netutil/check"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// Extension types the parser decodes.
const (
	extServerName = 0x00
	extALPN       = 0x10
)

// Extension is one extension of a ClientHello, as sent.
type Extension struct {
	// Type is the extension type.
	Type uint16
	// Body is the extension data, without the type and length fields.
	Body []byte
}

// serverName is one entry of a server_name extension.
type serverName struct {
	nameType byte
	hostName []byte
}

// extension is one parsed extension. names and protocols are set for the
// server_name and ALPN extensions.
type extension struct {
	Extension
	names     []serverName
	protocols [][]byte
}

// ClientHello is a parsed TLS ClientHello message. It is immutable: the
// accessors return copies.
type ClientHello struct {
	raw          []byte
	cipherSuites []uint16
	extensions   []extension
}

// NewClientHello parses raw, a ClientHello message body without the 4-byte
// handshake header, as mitmproxy's ClientHello(raw) does. It returns an
// error wrapping ErrMalformed when raw is not a ClientHello. NewClientHello
// keeps its own copy of raw.
//
// As in mitmproxy, the extensions are read up to the end of raw whatever
// length the extensions field declares, the server_name and ALPN extensions
// are decoded up to the end of their bodies whatever list length they
// declare, and a server_name or ALPN extension that cannot be decoded makes
// the whole message invalid.
func NewClientHello(raw []byte) (*ClientHello, error) {
	raw = bytes.Clone(raw)
	if raw == nil {
		raw = []byte{}
	}
	p := parser{buf: raw}
	ch := &ClientHello{raw: raw}

	p.skip(2)  // client_version
	p.skip(32) // random
	p.skip(int(p.u8()))
	// mitmproxy reads half the declared length's worth of suites; the odd
	// byte of an odd length is read as the compression methods' length.
	n := int(p.u16()) / 2
	if p.ok() && p.remaining() >= 2*n {
		ch.cipherSuites = make([]uint16, n)
		for i := range ch.cipherSuites {
			ch.cipherSuites[i] = p.u16()
		}
	} else {
		p.failed = true
	}
	p.skip(int(p.u8()))
	if p.ok() && p.remaining() > 0 {
		p.u16() // the declared length of the extensions, not used
		for p.ok() && p.remaining() > 0 {
			// The type is read before the length: operands are evaluated
			// left to right.
			ext := extension{Type: p.u16(), Body: p.bytes(int(p.u16()))}
			if !p.ok() {
				break
			}
			var ok bool
			switch ext.Type {
			case extServerName:
				ext.names, ok = parseServerNames(ext.Body)
			case extALPN:
				ext.protocols, ok = parseProtocols(ext.Body)
			default:
				ok = true
			}
			p.failed = !ok
			ch.extensions = append(ch.extensions, ext)
		}
	}
	if !p.ok() {
		return nil, fmt.Errorf("%w: invalid ClientHello", ErrMalformed)
	}
	return ch, nil
}

// parseServerNames decodes a server_name extension body.
func parseServerNames(body []byte) ([]serverName, bool) {
	p := parser{buf: body}
	p.u16() // the declared list length, not used
	var names []serverName
	for p.ok() && p.remaining() > 0 {
		var n serverName
		n.nameType = p.u8()
		n.hostName = p.bytes(int(p.u16()))
		names = append(names, n)
	}
	return names, p.ok()
}

// parseProtocols decodes an ALPN extension body.
func parseProtocols(body []byte) ([][]byte, bool) {
	p := parser{buf: body}
	p.u16() // the declared list length, not used
	var protocols [][]byte
	for p.ok() && p.remaining() > 0 {
		protocols = append(protocols, p.bytes(int(p.u8())))
	}
	return protocols, p.ok()
}

// SNI returns the Server Name Indication: the host name of the first
// server_name extension that holds exactly one name, of type host_name, that
// is a valid host name or IP address. It returns "" when there is none; a
// valid host name is never empty.
func (ch *ClientHello) SNI() string {
	for _, ext := range ch.extensions {
		if ext.Type == extServerName && len(ext.names) == 1 && ext.names[0].nameType == 0 && check.IsValidHost(ext.names[0].hostName) {
			return string(ext.names[0].hostName)
		}
	}
	return ""
}

// ALPNProtocols returns the application layer protocols of the first ALPN
// extension, or nil when there is none.
func (ch *ClientHello) ALPNProtocols() [][]byte {
	for _, ext := range ch.extensions {
		if ext.Type == extALPN {
			out := make([][]byte, len(ext.protocols))
			for i, p := range ext.protocols {
				out[i] = bytes.Clone(p)
			}
			return out
		}
	}
	return nil
}

// CipherSuites returns the cipher suites the client offers, in its order.
func (ch *ClientHello) CipherSuites() []uint16 {
	return slices.Clone(ch.cipherSuites)
}

// Extensions returns the extensions in the order the client sent them.
func (ch *ClientHello) Extensions() []Extension {
	if len(ch.extensions) == 0 {
		return nil
	}
	out := make([]Extension, len(ch.extensions))
	for i, ext := range ch.extensions {
		out[i] = Extension{Type: ext.Type, Body: bytes.Clone(ext.Body)}
	}
	return out
}

// RawBytes returns the ClientHello message body as the client sent it. With
// wrapInRecord, the body is wrapped in a synthetic TLS record and handshake
// header, the format some tools expect; the record version is always TLS
// 1.2, whatever the client sent, as in mitmproxy. The record header would
// hold a length that does not fit 16 bits for a body larger than 65,531
// bytes, so the wrapped form is nil for such a body; mitmproxy raises
// OverflowError there (docs/compat.md).
func (ch *ClientHello) RawBytes(wrapInRecord bool) []byte {
	if !wrapInRecord {
		return bytes.Clone(ch.raw)
	}
	n := len(ch.raw)
	if n > maxWrappedBodySize {
		return nil
	}
	out := make([]byte, 0, recordHeaderLen+handshakeHeaderLen+n)
	out = append(out, 0x16, 0x03, 0x03)
	out = binary.BigEndian.AppendUint16(out, uint16(n+handshakeHeaderLen)) //nolint:gosec // G115: bounded above.
	out = append(out, 0x01, byte(n>>16), byte(n>>8), byte(n))
	return append(out, ch.raw...)
}

// String returns the ClientHello as mitmproxy's repr shows it.
func (ch *ClientHello) String() string {
	b := []byte("ClientHello(sni: ")
	if sni := ch.SNI(); sni != "" {
		b = append(b, sni...)
	} else {
		b = append(b, "None"...)
	}
	b = append(b, ", alpn_protocols: ["...)
	for i, p := range ch.ALPNProtocols() {
		if i > 0 {
			b = append(b, ", "...)
		}
		b = pyrepr.AppendBytes(b, p)
	}
	return string(append(b, "])"...))
}

// parser reads big-endian fields from buf. The first read past the end
// sets failed; every later read returns zero values, so a sequence of reads
// needs one check at its end.
type parser struct {
	buf    []byte
	off    int
	failed bool
}

func (p *parser) ok() bool { return !p.failed }

func (p *parser) remaining() int { return len(p.buf) - p.off }

// bytes returns the next n bytes, a subslice of buf.
func (p *parser) bytes(n int) []byte {
	if !p.ok() {
		return nil
	}
	if p.remaining() < n {
		p.failed = true
		return nil
	}
	b := p.buf[p.off : p.off+n : p.off+n]
	p.off += n
	return b
}

func (p *parser) skip(n int) { p.bytes(n) }

func (p *parser) u8() byte {
	if b := p.bytes(1); b != nil {
		return b[0]
	}
	return 0
}

func (p *parser) u16() uint16 {
	if b := p.bytes(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}
