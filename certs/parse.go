// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf16"
)

// ParseCert parses the first CERTIFICATE block of PEM-encoded data, as
// mitmproxy's Cert.from_pem does.
func ParseCert(data []byte) (*Cert, error) {
	for rest := data; ; {
		block, after := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("certs: no CERTIFICATE block in PEM data")
		}
		if block.Type == "CERTIFICATE" {
			x, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("certs: parse certificate: %w", err)
			}
			return NewCert(x), nil
		}
		rest = after
	}
}

// nameAttr is one attribute of a parsed distinguished name.
type nameAttr struct {
	oid asn1.ObjectIdentifier
	val string
}

// rfc4514ShortNames maps the attribute types that RFC 4514 gives a short
// name, which is how mitmproxy's subject and issuer lists render keys;
// every other type renders as its dotted OID.
var rfc4514ShortNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.6":                    "C",
	"2.5.4.9":                    "STREET",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
}

// oidCommonName and oidOrganization are the subject attributes Cert.CN
// and Cert.Organization read.
var (
	oidCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrganization = asn1.ObjectIdentifier{2, 5, 4, 10}
)

// parseName parses a raw DER RDNSequence into its attributes in encoded
// order, multi-valued RDNs flattened in place, as iterating a
// cryptography x509.Name yields them. Go's pkix.Name is not used because
// it regroups the attributes by type.
func parseName(raw []byte) ([]nameAttr, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil {
		return nil, fmt.Errorf("certs: parse name: %w", err)
	}
	if len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("certs: name is not an RDNSequence")
	}

	var attrs []nameAttr
	for data := seq.Bytes; len(data) > 0; {
		var set asn1.RawValue
		data, err = asn1.Unmarshal(data, &set)
		if err != nil {
			return nil, fmt.Errorf("certs: parse RDN: %w", err)
		}
		for inner := set.Bytes; len(inner) > 0; {
			var atv asn1.RawValue
			inner, err = asn1.Unmarshal(inner, &atv)
			if err != nil {
				return nil, fmt.Errorf("certs: parse name attribute: %w", err)
			}
			var oid asn1.ObjectIdentifier
			valDER, err := asn1.Unmarshal(atv.Bytes, &oid)
			if err != nil {
				return nil, fmt.Errorf("certs: parse name attribute type: %w", err)
			}
			var val asn1.RawValue
			if _, err := asn1.Unmarshal(valDER, &val); err != nil {
				return nil, fmt.Errorf("certs: parse name attribute value: %w", err)
			}
			attrs = append(attrs, nameAttr{oid: oid, val: decodeNameString(val)})
		}
	}
	return attrs, nil
}

// decodeNameString decodes an attribute value of any of the ASN.1 string
// types a name can carry. An unknown type's bytes are kept as they are.
func decodeNameString(v asn1.RawValue) string {
	const (
		tagBMPString       = 30
		tagUniversalString = 28
	)
	switch v.Tag {
	case tagBMPString:
		u := make([]uint16, 0, len(v.Bytes)/2)
		for i := 0; i+1 < len(v.Bytes); i += 2 {
			u = append(u, uint16(v.Bytes[i])<<8|uint16(v.Bytes[i+1]))
		}
		return string(utf16.Decode(u))
	case tagUniversalString:
		runes := make([]rune, 0, len(v.Bytes)/4)
		for i := 0; i+3 < len(v.Bytes); i += 4 {
			runes = append(runes, rune(uint32(v.Bytes[i])<<24|uint32(v.Bytes[i+1])<<16|uint32(v.Bytes[i+2])<<8|uint32(v.Bytes[i+3])))
		}
		return string(runes)
	default:
		// UTF8String, PrintableString, IA5String, NumericString and
		// T61String bytes are the text itself.
		return string(v.Bytes)
	}
}

// keyVals renders parsed name attributes as mitmproxy renders a name:
// the RFC 4514 short name when there is one, else the dotted OID.
func keyVals(attrs []nameAttr) []KeyVal {
	out := make([]KeyVal, len(attrs))
	for i, a := range attrs {
		key, ok := rfc4514ShortNames[a.oid.String()]
		if !ok {
			key = a.oid.String()
		}
		out[i] = KeyVal{Key: key, Value: a.val}
	}
	return out
}

// Extension OIDs the package reads from the raw certificate.
var (
	oidSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
)

// SAN GeneralName context tags (RFC 5280 section 4.2.1.6).
const (
	tagRFC822Name = 1
	tagDNSName    = 2
	tagURI        = 6
	tagIPAddress  = 7
)

// parseGeneralNames parses the value of a SubjectAlternativeName
// extension in encoded order. An entry of a type the package does not
// model, or an IP address entry of an impossible length, is kept raw as
// a [GeneralNameOther]. Parsing a complete certificate still uses
// crypto/x509's validation before reaching this function.
func parseGeneralNames(der []byte) ([]GeneralName, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, fmt.Errorf("certs: parse SAN extension: %w", err)
	}
	if len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("certs: SAN extension is not a GeneralNames sequence")
	}

	names := []GeneralName{}
	for data := seq.Bytes; len(data) > 0; {
		var v asn1.RawValue
		data, err = asn1.Unmarshal(data, &v)
		if err != nil {
			return nil, fmt.Errorf("certs: parse SAN entry %d: %w", len(names), err)
		}
		if v.Class != asn1.ClassContextSpecific {
			names = append(names, otherName(v.FullBytes))
			continue
		}
		switch v.Tag {
		case tagDNSName:
			names = append(names, DNSName(string(v.Bytes)))
		case tagRFC822Name:
			names = append(names, EmailName(string(v.Bytes)))
		case tagURI:
			names = append(names, URIName(string(v.Bytes)))
		case tagIPAddress:
			switch len(v.Bytes) {
			case 4:
				names = append(names, IPAddress(netip.AddrFrom4([4]byte(v.Bytes))))
			case 16:
				names = append(names, IPAddress(netip.AddrFrom16([16]byte(v.Bytes))))
			default:
				names = append(names, otherName(v.FullBytes))
			}
		default:
			names = append(names, otherName(v.FullBytes))
		}
	}
	return names, nil
}

// parseCRLDistributionPoints returns, for every distribution point whose
// name is present and whose first general name is a URI, that URI, as
// mitmproxy's crl_distribution_points does.
func parseCRLDistributionPoints(der []byte) ([]string, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, fmt.Errorf("certs: parse CRL distribution points: %w", err)
	}
	if len(rest) != 0 || seq.Tag != asn1.TagSequence {
		return nil, errors.New("certs: CRL distribution points is not a sequence")
	}

	urls := []string{}
	for data := seq.Bytes; len(data) > 0; {
		var dp asn1.RawValue
		data, err = asn1.Unmarshal(data, &dp)
		if err != nil {
			return nil, fmt.Errorf("certs: parse distribution point: %w", err)
		}
		// DistributionPoint ::= SEQUENCE { distributionPoint [0] EXPLICIT
		// DistributionPointName OPTIONAL, ... }; DistributionPointName ::=
		// CHOICE { fullName [0] GeneralNames, ... }.
		var dpName asn1.RawValue
		if _, err := asn1.Unmarshal(dp.Bytes, &dpName); err != nil || dpName.Class != asn1.ClassContextSpecific || dpName.Tag != 0 {
			continue
		}
		var fullName asn1.RawValue
		if _, err := asn1.Unmarshal(dpName.Bytes, &fullName); err != nil || fullName.Class != asn1.ClassContextSpecific || fullName.Tag != 0 {
			continue
		}
		var first asn1.RawValue
		if _, err := asn1.Unmarshal(fullName.Bytes, &first); err != nil {
			continue
		}
		if first.Class == asn1.ClassContextSpecific && first.Tag == tagURI {
			urls = append(urls, string(first.Bytes))
		}
	}
	return urls, nil
}
