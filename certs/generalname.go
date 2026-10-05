// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"encoding/hex"
	"net/netip"
)

// GeneralNameType identifies which kind of name a [GeneralName] holds.
type GeneralNameType int

// The GeneralName kinds the proxy works with. Any other X.509 general
// name type (directory names, registered IDs, ...) is carried opaquely
// as [GeneralNameOther].
const (
	GeneralNameDNS GeneralNameType = iota
	GeneralNameIP
	GeneralNameURI
	GeneralNameEmail
	GeneralNameOther
)

// String returns the name of the type, for example "DNS" or "IP".
func (t GeneralNameType) String() string {
	switch t {
	case GeneralNameDNS:
		return "DNS"
	case GeneralNameIP:
		return "IP"
	case GeneralNameURI:
		return "URI"
	case GeneralNameEmail:
		return "email"
	case GeneralNameOther:
		return "other"
	default:
		return "unknown"
	}
}

// GeneralName is one X.509 GeneralName: a subject alternative name of a
// certificate, or a name a leaf is requested for. It is comparable, so
// names can be map keys and compared with ==. The zero value is a DNS
// name of the empty string.
//
// It is the counterpart of cryptography's x509.GeneralName values that
// mitmproxy passes around as SANs.
type GeneralName struct {
	typ GeneralNameType

	// text holds the DNS name, URI or email address; for GeneralNameOther
	// it holds the DER-encoded name, so that unknown SAN entries survive a
	// parse/build round trip.
	text string
	ip   netip.Addr
}

// DNSName returns the GeneralName for a DNS name. The name is stored as
// given: callers pass IDNA-encoded (punycode) names, as mitmproxy does.
func DNSName(name string) GeneralName {
	return GeneralName{typ: GeneralNameDNS, text: name}
}

// IPAddress returns the GeneralName for an IP address.
func IPAddress(addr netip.Addr) GeneralName {
	return GeneralName{typ: GeneralNameIP, ip: addr}
}

// URIName returns the GeneralName for a uniformResourceIdentifier name.
func URIName(uri string) GeneralName {
	return GeneralName{typ: GeneralNameURI, text: uri}
}

// EmailName returns the GeneralName for an rfc822Name (email address).
func EmailName(email string) GeneralName {
	return GeneralName{typ: GeneralNameEmail, text: email}
}

// Type reports which kind of name n holds.
func (n GeneralName) Type() GeneralNameType {
	return n.typ
}

// IP returns the address of a [GeneralNameIP] name; for every other type
// it returns the zero [netip.Addr].
func (n GeneralName) IP() netip.Addr {
	return n.ip
}

// String returns the name's value as text, as Python's str(name.value)
// renders it: the DNS name, the address ("127.0.0.1"), the URI or the
// email address. A [GeneralNameOther] name renders as the hex of its DER
// encoding.
func (n GeneralName) String() string {
	switch n.typ {
	case GeneralNameIP:
		return n.ip.String()
	case GeneralNameOther:
		return hex.EncodeToString([]byte(n.text))
	default:
		return n.text
	}
}
