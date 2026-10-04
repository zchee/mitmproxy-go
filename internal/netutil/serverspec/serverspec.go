// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package serverspec parses server specifications, which describe an
// upstream proxy or server, the way mitmproxy's mitmproxy/net/server_spec.py
// does: "http://example.com/", "example.org" or "example.com:443".
package serverspec

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/netutil/check"
)

// Address is a host and port pair. Host holds an IPv6 address without
// brackets.
type Address struct {
	Host string
	Port int
}

// Reason classifies a parse failure.
type Reason int

// The reasons Parse can fail, in the order Parse checks them.
const (
	// InvalidSpecification means the spec does not have the shape
	// [scheme://]host[:port][/].
	InvalidSpecification Reason = iota
	// InvalidScheme means the scheme is not one Parse accepts.
	InvalidScheme
	// InvalidHostname means the host fails check.IsValidHost.
	InvalidHostname
	// MissingPort means the spec has no port and the scheme has no default.
	MissingPort
	// InvalidPort means the port is outside 0 to 65535.
	InvalidPort
)

// Error is the error Parse returns. Its message is upstream's ValueError
// text, which mitmproxy shows to users verbatim.
type Error struct {
	Reason Reason
	// Value is the spec, scheme, host or port that failed, as written.
	Value string
}

// Error implements the error interface.
func (e *Error) Error() string {
	switch e.Reason {
	case InvalidSpecification:
		return "Invalid server specification: " + e.Value
	case InvalidScheme:
		return "Invalid server scheme: " + e.Value
	case InvalidHostname:
		return "Invalid hostname: " + e.Value
	case MissingPort:
		return "Port specification missing."
	case InvalidPort:
		return "Invalid port: " + e.Value
	}
	return "Invalid server specification: " + e.Value
}

// specRE matches an optional scheme, a host that is a name, an IPv4
// address or a bracketed IPv6 address, an optional port and an optional
// trailing slash, but no path. Go's regexp uses the same leftmost-first
// submatch semantics as Python's re.
var specRE = regexp.MustCompile(`^(?:(\w+)://)?([^:/]+|\[.+\])(?::(\d+))?/?$`)

// schemes holds the accepted schemes with their default port, or 0 when the
// spec must name a port.
var schemes = map[string]int{
	"http":  80,
	"https": 443,
	"http3": 443,
	"tls":   0,
	"dtls":  0,
	"tcp":   0,
	"udp":   0,
	"dns":   53,
	"quic":  443,
}

// Parse parses spec, using defaultScheme when spec has no scheme. Schemes
// are case-sensitive. The accepted schemes are http, https, http3, tls,
// dtls, tcp, udp, dns and quic; http defaults to port 80, https, http3 and
// quic to 443, and dns to 53, while the others need an explicit port.
//
// The returned error is an *Error.
func Parse(spec, defaultScheme string) (scheme string, address Address, err error) {
	m := specRE.FindStringSubmatch(spec)
	if m == nil {
		return "", Address{}, &Error{Reason: InvalidSpecification, Value: spec}
	}

	scheme = m[1]
	if scheme == "" {
		scheme = defaultScheme
	}
	defaultPort, ok := schemes[scheme]
	if !ok {
		return "", Address{}, &Error{Reason: InvalidScheme, Value: scheme}
	}

	host := m[2]
	if inner, ok := strings.CutPrefix(host, "["); ok {
		if inner, ok := strings.CutSuffix(inner, "]"); ok {
			host = inner
		}
	}
	if !check.IsValidHost(host) {
		return "", Address{}, &Error{Reason: InvalidHostname, Value: host}
	}

	port := defaultPort
	if m[3] != "" {
		port, err = strconv.Atoi(m[3])
		if err != nil || !check.IsValidPort(port) {
			// An overflowing port is reported as written, as Python's
			// arbitrary-precision int would print it.
			value := strings.TrimLeft(m[3], "0")
			if value == "" {
				value = "0"
			}
			return "", Address{}, &Error{Reason: InvalidPort, Value: value}
		}
	} else if defaultPort == 0 {
		return "", Address{}, &Error{Reason: MissingPort}
	}
	return scheme, Address{Host: host, Port: port}, nil
}
