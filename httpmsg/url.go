// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/zchee/mitmproxy-go/internal/netutil/check"
)

// idnaProfile approximates the IDNA 2003 ToASCII operation of Python's
// "idna" codec, the same way the check package does.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(false))

// idnaEncode converts the non-ASCII labels of host to Punycode, as
// Python's str.encode("idna") does. ASCII input is returned unchanged:
// where Python's codec would reject it, upstream falls back to the UTF-8
// bytes, which are the same.
func idnaEncode(host string) (string, bool) {
	if isASCII(host) {
		return host, true
	}
	labels := strings.Split(host, ".")
	for i, l := range labels {
		if isASCII(l) {
			continue
		}
		a, err := idnaProfile.ToASCII(l)
		if err != nil {
			return "", false
		}
		labels[i] = a
	}
	return strings.Join(labels, "."), true
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// DefaultPort returns the default port of the http and https schemes, and
// false for any other scheme.
func DefaultPort(scheme string) (int, bool) {
	switch scheme {
	case "http":
		return 80, true
	case "https":
		return 443, true
	}
	return 0, false
}

// HostPort returns host, followed by ":port" unless port is the scheme's
// default port.
func HostPort(scheme, host string, port int) string {
	if p, ok := DefaultPort(scheme); ok && p == port {
		return host
	}
	return host + ":" + strconv.Itoa(port)
}

// UnparseURL builds "scheme://authority/path" from its parts, omitting the
// port when it is the scheme's default.
func UnparseURL(scheme, host string, port int, path string) string {
	return scheme + "://" + HostPort(scheme, host, port) + path
}

var authorityRE = regexp.MustCompile(`^([^:]+|\[.+\])(?::(\d+))?$`)

// errAuthority is returned by ParseAuthority for malformed input.
var errAuthority = errors.New("invalid authority")

// ParseAuthority splits Host header or authority information into host and
// port. IPv6 brackets are removed. The port is -1 when absent.
//
// When strict is false a malformed value is returned whole as the host with
// port -1 instead of failing.
func ParseAuthority(authority string, strict bool) (host string, port int, err error) {
	fail := func() (string, int, error) {
		if strict {
			return "", -1, errAuthority
		}
		return authority, -1, nil
	}
	m := authorityRE.FindStringSubmatch(authority)
	if m == nil {
		return fail()
	}
	host = m[1]
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if !check.IsValidHost(host) {
		return fail()
	}
	if m[2] == "" {
		return host, -1, nil
	}
	port, convErr := strconv.Atoi(m[2])
	if convErr != nil || !check.IsValidPort(port) {
		return fail()
	}
	return host, port, nil
}

// urlsplit splits a URL into scheme (lower-cased), netloc, path, query and
// fragment, as Python's urllib.parse.urlsplit does, including its rejection
// of unbalanced or invalid IPv6 brackets in the netloc.
func urlsplit(u string) (scheme, netloc, path, query, fragment string, err error) {
	u = strings.TrimLeft(u, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ")
	u = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, u)
	if i := strings.IndexByte(u, ':'); i > 0 && isSchemeStart(u[0]) && isScheme(u[:i]) {
		scheme, u = strings.ToLower(u[:i]), u[i+1:]
	}
	if strings.HasPrefix(u, "//") {
		end := len(u)
		if i := strings.IndexAny(u[2:], "/?#"); i >= 0 {
			end = i + 2
		}
		netloc, u = u[2:end], u[end:]
		open, closed := strings.Contains(netloc, "["), strings.Contains(netloc, "]")
		if open != closed {
			return "", "", "", "", "", errors.New("invalid IPv6 URL")
		}
		if open {
			_, hostport, _ := strings.Cut(netloc, "[")
			bracketed, _, _ := strings.Cut(hostport, "]")
			if !strings.HasPrefix(bracketed, "v") {
				if ip, err := netip.ParseAddr(bracketed); err != nil || !ip.Is6() {
					return "", "", "", "", "", errors.New("invalid IPv6 URL")
				}
			}
		}
	}
	u, fragment, _ = strings.Cut(u, "#")
	path, query, _ = strings.Cut(u, "?")
	return scheme, netloc, path, query, fragment, nil
}

// urlunsplit is the inverse of urlsplit, following Python's urlunsplit.
func urlunsplit(scheme, netloc, path, query, fragment string) string {
	switch {
	case netloc != "":
		if path != "" && path[0] != '/' {
			path = "/" + path
		}
		path = "//" + netloc + path
	case strings.HasPrefix(path, "//"):
		path = "//" + path
	case scheme != "" && usesNetloc(scheme) && (path == "" || path[0] == '/'):
		path = "//" + path
	}
	if scheme != "" {
		path = scheme + ":" + path
	}
	if query != "" {
		path += "?" + query
	}
	if fragment != "" {
		path += "#" + fragment
	}
	return path
}

// splitParams splits ";params" off the last path segment, as urlparse does
// for schemes that use parameters.
func splitParams(path string) (string, string) {
	i := strings.IndexByte(path, ';')
	if j := strings.LastIndexByte(path, '/'); j >= 0 {
		if i = strings.IndexByte(path[j:], ';'); i >= 0 {
			i += j
		}
	}
	if i < 0 {
		return path, ""
	}
	return path[:i], path[i+1:]
}

func usesNetloc(scheme string) bool {
	switch scheme {
	case "ftp", "http", "gopher", "nntp", "telnet", "imap", "wais", "file", "mms", "https", "shttp", "snews",
		"prospero", "rtsp", "rtsps", "rtspu", "rsync", "svn", "svn+ssh", "sftp", "nfs", "git", "git+ssh", "ws", "wss", "itms-services":
		return true
	}
	return false
}

func isSchemeStart(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func isScheme(s string) bool {
	for i := range len(s) {
		c := s[i]
		if !isSchemeStart(c) && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func usesParams(scheme string) bool {
	switch scheme {
	case "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu", "sip", "sips", "mms", "sftp", "tel":
		return true
	}
	return false
}

// netlocHostPort extracts the lower-cased host and the port string from a
// netloc, as urllib's hostname and port properties do.
func netlocHostPort(netloc string) (host, port string) {
	if i := strings.LastIndexByte(netloc, '@'); i >= 0 {
		netloc = netloc[i+1:]
	}
	if strings.HasPrefix(netloc, "[") {
		h, rest, _ := strings.Cut(netloc[1:], "]")
		_, port, _ = strings.Cut(rest, ":")
		return strings.ToLower(h), port
	}
	host, port, _ = strings.Cut(netloc, ":")
	return strings.ToLower(host), port
}

// ParseURLBytes is ParseURL for a raw request target, as upstream's
// url.parse handles bytes: a UTF-8 target whose query holds non-ASCII text
// has its query percent-encoded first instead of being rejected.
func ParseURLBytes(u []byte) (scheme, host string, port int, path string, err error) {
	s := string(u)
	if !isASCII(s) {
		if !utf8.ValidString(s) {
			return "", "", 0, "", errors.New("URL is not valid UTF-8")
		}
		sc, n, p, q, f, err := urlsplit(s)
		if err != nil {
			return "", "", 0, "", err
		}
		s = urlunsplit(sc, n, p, Quote(q, "/"), f)
	}
	return ParseURL(s)
}

// ParseURL splits an absolute URL into scheme, host, port and path (with
// query and fragment), as upstream's url.parse does for a str. The host
// must be a valid hostname or IP address, the port in range and the URL
// ASCII; a missing port defaults to 443 for https and 80 otherwise.
func ParseURL(u string) (scheme, host string, port int, path string, err error) {
	fail := func(msg string) (string, string, int, string, error) {
		return "", "", 0, "", errors.New(msg)
	}
	scheme, netloc, p, query, fragment, err := urlsplit(u)
	if err != nil {
		return "", "", 0, "", err
	}
	params := ""
	if usesParams(scheme) {
		p, params = splitParams(p)
	}
	host, portStr := netlocHostPort(netloc)
	if host == "" {
		return fail("no hostname given")
	}
	if !isASCII(u) {
		return fail("URL must be ASCII")
	}
	if portStr != "" {
		for i := range len(portStr) {
			if portStr[i] < '0' || portStr[i] > '9' {
				return fail("port could not be cast to integer value")
			}
		}
		port, err = strconv.Atoi(portStr)
		if err != nil || !check.IsValidPort(port) {
			return fail("port out of range 0-65535")
		}
	}
	if port == 0 {
		port = 80
		if scheme == "https" {
			port = 443
		}
	}
	if params != "" {
		p += ";" + params
	}
	path = urlunsplit("", "", p, query, fragment)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !check.IsValidHost(host) {
		return fail("invalid host")
	}
	return scheme, host, port, path, nil
}

// alwaysSafe are the bytes Python's urllib.parse.quote never escapes.
const alwaysSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~"

// Quote percent-encodes every byte of s except ASCII letters, digits,
// "_.-~" and the bytes in safe, as Python's urllib.parse.quote does.
// Upstream uses safe="/" by default.
func Quote(s, safe string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if strings.IndexByte(alwaysSafe, c) >= 0 || strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// Unquote replaces %XX escapes with the bytes they encode. Malformed escapes
// are kept as they are, as Python's urllib.parse.unquote keeps them.
func Unquote(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := unhex(s[i+1]); ok {
				if lo, ok := unhex(s[i+2]); ok {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
