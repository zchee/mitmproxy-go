// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"bytes"
	"regexp"
	"strings"
)

// contentType is a parsed Content-Type value. Params keep their order.
type contentType struct {
	Type    string
	Subtype string
	Params  [][2]string
}

// parseContentType parses a Content-Type value such as
// "text/html; charset=UTF-8" the way upstream's simple parser does: type and
// subtype are lower-cased, parameter names and values are trimmed, and
// clauses without "=" are skipped. It reports false when the value has no
// "/" in its media type.
func parseContentType(c string) (contentType, bool) {
	media, params, hasParams := strings.Cut(c, ";")
	typ, sub, ok := strings.Cut(media, "/")
	if !ok {
		return contentType{}, false
	}
	ct := contentType{Type: strings.ToLower(typ), Subtype: strings.ToLower(sub)}
	if hasParams {
		for clause := range strings.SplitSeq(params, ";") {
			k, v, ok := strings.Cut(clause, "=")
			if ok {
				ct.setParam(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
	}
	return ct, true
}

// param returns the value of the named parameter. Names match exactly, as
// upstream's dict lookup does.
func (c contentType) param(name string) (string, bool) {
	for _, p := range c.Params {
		if p[0] == name {
			return p[1], true
		}
	}
	return "", false
}

// setParam sets a parameter, keeping its position when it already exists.
func (c *contentType) setParam(name, value string) {
	for i := range c.Params {
		if c.Params[i][0] == name {
			c.Params[i][1] = value
			return
		}
	}
	c.Params = append(c.Params, [2]string{name, value})
}

// String assembles the value as "type/subtype; k=v; k2=v2".
func (c contentType) String() string {
	var b strings.Builder
	b.WriteString(c.Type)
	b.WriteByte('/')
	b.WriteString(c.Subtype)
	for _, p := range c.Params {
		b.WriteString("; ")
		b.WriteString(p[0])
		b.WriteByte('=')
		b.WriteString(p[1])
	}
	return b.String()
}

var (
	metaCharsetRE = regexp.MustCompile(`(?i)<meta[^>]+charset=['"]?([^'">]+)`)
	xmlEncodingRE = regexp.MustCompile(`(?i)<\?xml[^?>]+encoding=['"]([^'"?>]+)`)
	cssCharsetRE  = regexp.MustCompile(`(?i)^@charset "([^"]+)";`)
)

// asciiIgnore keeps the ASCII bytes of b, as Python's decode("ascii",
// "ignore") does.
func asciiIgnore(b []byte) string {
	return string(bytes.Map(func(r rune) rune {
		if r < 0x80 {
			return r
		}
		return -1
	}, b))
}

// inferContentEncoding infers the character set of a body from a byte order
// mark, the Content-Type charset, or hints inside HTML, XML and CSS bodies,
// falling back to UTF-8 for text formats that default to it and to Latin-1
// otherwise. GB2312 and GBK map to their superset GB18030.
func inferContentEncoding(contentTypeValue string, content []byte) string {
	var enc string
	switch {
	case bytes.HasPrefix(content, []byte("\x00\x00\xfe\xff")):
		enc = "utf-32be"
	case bytes.HasPrefix(content, []byte("\xff\xfe\x00\x00")):
		enc = "utf-32le"
	case bytes.HasPrefix(content, []byte("\xfe\xff")):
		enc = "utf-16be"
	case bytes.HasPrefix(content, []byte("\xff\xfe")):
		enc = "utf-16le"
	case bytes.HasPrefix(content, []byte("\xef\xbb\xbf")):
		enc = "utf-8-sig"
	default:
		if ct, ok := parseContentType(contentTypeValue); ok {
			enc, _ = ct.param("charset")
		}
	}

	if enc == "" && strings.Contains(contentTypeValue, "json") {
		enc = "utf8"
	}
	if enc == "" && strings.Contains(contentTypeValue, "html") {
		if m := metaCharsetRE.FindSubmatch(content); m != nil {
			enc = asciiIgnore(m[1])
		} else {
			enc = "utf8"
		}
	}
	if enc == "" && strings.Contains(contentTypeValue, "xml") {
		if m := xmlEncodingRE.FindSubmatch(content); m != nil {
			enc = asciiIgnore(m[1])
		} else {
			enc = "utf8"
		}
	}
	if enc == "" && (strings.Contains(contentTypeValue, "javascript") || strings.Contains(contentTypeValue, "ecmascript")) {
		enc = "utf8"
	}
	if enc == "" && strings.Contains(contentTypeValue, "text/css") {
		if m := cssCharsetRE.FindSubmatch(content); m != nil {
			enc = asciiIgnore(m[1])
		} else {
			enc = "utf8"
		}
	}
	if enc == "" {
		enc = "latin-1"
	}
	if l := strings.ToLower(enc); l == "gb2312" || l == "gbk" {
		enc = "gb18030"
	}
	return enc
}
