// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package check validates host names and ports the way mitmproxy's
// mitmproxy/net/check.py does.
package check

import (
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// maxHostLen is the RFC 1035 limit on the length of a domain name.
const maxHostLen = 255

// acePrefix marks a Punycode-encoded IDNA label.
const acePrefix = "xn--"

// idnaProfile approximates the IDNA 2003 ToASCII operation that Python's
// "idna" codec performs: UTS #46 transitional processing maps characters as
// nameprep does (for example "ß" to "ss"), and STD3 rules stay off because
// Python's codec does not apply them either. The tables differ in detail, as
// UTS #46 tracks the current Unicode version and nameprep is fixed at
// Unicode 3.2.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(false))

// IsValidHost reports whether host is a valid DNS name, a valid IPv4
// address or a valid IPv6 address.
//
// As upstream accepts both str and bytes, so does IsValidHost, and with the
// same difference: a string is IDNA-encoded first, so "münchen.de" is
// valid, whereas a byte slice must already be ASCII and is only checked for
// well-formed "xn--" labels. Labels may contain underscores and may start
// or end with a hyphen.
//
// Unlike upstream, a host that ends in a newline is invalid; Python's "$"
// regular expression anchor accepts one there. An IPv6 zone must also be an
// RFC 6874 ZoneID, where upstream accepts any zone without "%" or "/".
func IsValidHost[T string | []byte](host T) bool {
	switch h := any(host).(type) {
	case string:
		encoded, ok := encodeIDNA(h)
		return ok && isValidHostBytes(encoded)
	case []byte:
		return isValidHostBytes(string(h))
	}
	return false
}

// IsValidPort reports whether port is in the range 0 to 65535.
func IsValidPort(port int) bool {
	return 0 <= port && port <= 65535
}

// isValidHostBytes implements upstream's check for an ASCII host, held in a
// string for convenience.
func isValidHostBytes(host string) bool {
	if !decodesAsIDNA(host) {
		return false
	}
	if len(host) > maxHostLen {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if allLabelsValid(host) {
		return true
	}
	if _, zone, ok := strings.Cut(host, "%"); ok && !isZoneID(zone) {
		return false
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

// isZoneID reports whether zone matches RFC 6874's ZoneID, one or more
// unreserved characters or percent-encoded octets. netip and Python's
// ipaddress accept nearly any byte in a zone, but a host flows into names
// such as the client certificate file of a server, where a path separator
// or a NUL must never arrive from a peer.
func isZoneID(zone string) bool {
	if zone == "" {
		return false
	}
	for i := 0; i < len(zone); i++ {
		switch c := zone[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', strings.IndexByte("-._~", c) >= 0:
		case c == '%' && i+2 < len(zone) && isHex(zone[i+1]) && isHex(zone[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func allLabelsValid(host string) bool {
	for label := range strings.SplitSeq(host, ".") {
		if !isValidLabel(label) {
			return false
		}
	}
	return true
}

// isValidLabel reports whether label is 1 to 63 letters, digits, hyphens
// or underscores.
func isValidLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	for i := range len(label) {
		switch c := label[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// decodesAsIDNA reports whether Python's bytes.decode("idna") accepts host:
// every byte is ASCII and every "xn--" label decodes from Punycode to a
// label whose ToASCII form is the original label.
func decodesAsIDNA(host string) bool {
	if !isASCII(host) {
		return false
	}
	if !strings.Contains(strings.ToLower(host), acePrefix) {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	for label := range strings.SplitSeq(host, ".") {
		if !strings.HasPrefix(strings.ToLower(label), acePrefix) {
			continue
		}
		decoded, err := idna.Punycode.ToUnicode(strings.ToLower(label))
		if err != nil {
			return false
		}
		reencoded, ok := labelToASCII(decoded)
		if !ok || reencoded != strings.ToLower(label) {
			return false
		}
	}
	return true
}

// encodeIDNA mirrors Python's str.encode("idna").
func encodeIDNA(host string) (string, bool) {
	if host == "" {
		return "", true
	}
	if isASCII(host) {
		labels := strings.Split(host, ".")
		for _, label := range labels[:len(labels)-1] {
			if len(label) == 0 || len(label) > 63 {
				return "", false
			}
		}
		return host, len(labels[len(labels)-1]) < 64
	}
	labels := splitIDNADots(host)
	trailingDot := ""
	if labels[len(labels)-1] == "" {
		trailingDot = "."
		labels = labels[:len(labels)-1]
	}
	var b strings.Builder
	for i, label := range labels {
		encoded, ok := labelToASCII(label)
		if !ok {
			return "", false
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(encoded)
	}
	b.WriteString(trailingDot)
	return b.String(), true
}

// labelToASCII mirrors the IDNA 2003 ToASCII operation on a single label.
func labelToASCII(label string) (string, bool) {
	if isASCII(label) {
		return label, len(label) > 0 && len(label) < 64
	}
	// A non-ASCII label must not already carry the ACE prefix.
	if strings.HasPrefix(strings.ToLower(label), acePrefix) {
		return "", false
	}
	encoded, err := idnaProfile.ToASCII(label)
	if err != nil {
		return "", false
	}
	return encoded, len(encoded) > 0 && len(encoded) < 64
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// isIDNADot reports whether r is one of the label separators Python's
// "idna" codec recognises.
func isIDNADot(r rune) bool {
	switch r {
	case '.', '。', '．', '｡':
		return true
	}
	return false
}

func splitIDNADots(s string) []string {
	var labels []string
	start := 0
	for i, r := range s {
		if isIDNADot(r) {
			labels = append(labels, s[start:i])
			start = i + len(string(r))
		}
	}
	return append(labels, s[start:])
}
