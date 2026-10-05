// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/stateutil"
)

// QuotePlus is [Quote] with an empty safe set, except that spaces become
// "+", as Python's urllib.parse.quote_plus does for form encoding.
func QuotePlus(s string) string {
	if !strings.Contains(s, " ") {
		return Quote(s, "")
	}
	return strings.ReplaceAll(Quote(s, " "), " ", "+")
}

// EncodeQuery encodes (key, value) pairs as application/x-www-form-urlencoded
// text, as upstream's url.encode does. When similarTo is given and one of
// its fields has no "=", fields with empty values are written without the
// trailing "=" too, so that a rewritten query keeps the client's style.
func EncodeQuery(pairs [][2]string, similarTo string) string {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(QuotePlus(p[0]))
		b.WriteByte('=')
		b.WriteString(QuotePlus(p[1]))
	}
	encoded := b.String()
	removeTrailingEqual := false
	if similarTo != "" {
		for field := range strings.SplitSeq(similarTo, "&") {
			if !strings.Contains(field, "=") {
				removeTrailingEqual = true
				break
			}
		}
	}
	if encoded != "" && removeTrailingEqual {
		encoded = strings.ReplaceAll(encoded, "=&", "&")
		encoded = strings.TrimSuffix(encoded, "=")
	}
	return encoded
}

// DecodeQuery parses application/x-www-form-urlencoded text into (key,
// value) pairs, keeping fields with blank values, as Python's
// urllib.parse.parse_qsl(keep_blank_values=True) does. Escapes that do not
// form valid UTF-8 are kept as raw bytes.
func DecodeQuery(s string) [][2]string {
	var out [][2]string
	for field := range strings.SplitSeq(s, "&") {
		if field == "" {
			continue
		}
		name, value, _ := strings.Cut(field, "=")
		out = append(out, [2]string{
			Unquote(strings.ReplaceAll(name, "+", " ")),
			Unquote(strings.ReplaceAll(value, "+", " ")),
		})
	}
	return out
}

// splitRequestURL splits the request's URL into the parts urlparse gives.
func (r *Request) splitRequestURL() (path, params, query, fragment string) {
	_, _, p, q, f, err := urlsplit(r.URL())
	if err != nil {
		return "", "", "", ""
	}
	p, params = splitParams(p)
	return p, params, q, f
}

func (r *Request) setPathParts(path, params, query, fragment string) {
	if params != "" {
		path += ";" + params
	}
	r.Path = urlunsplit("", "", path, query, fragment)
}

// Query returns the query parameters of the request path, in order.
func (r *Request) Query() [][2]string {
	_, _, q, _ := r.splitRequestURL()
	return DecodeQuery(q)
}

// SetQuery replaces the query of the request path with the given
// parameters.
func (r *Request) SetQuery(pairs [][2]string) {
	path, params, _, fragment := r.splitRequestURL()
	r.setPathParts(path, params, EncodeQuery(pairs, ""), fragment)
}

// PathComponents returns the non-empty segments of the URL path, unquoted.
func (r *Request) PathComponents() []string {
	path, _, _, _ := r.splitRequestURL()
	var out []string
	for seg := range strings.SplitSeq(path, "/") {
		if seg != "" {
			out = append(out, Unquote(seg))
		}
	}
	return out
}

// SetPathComponents replaces the URL path with the given segments, each
// fully quoted, keeping the query and fragment.
func (r *Request) SetPathComponents(components []string) {
	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = Quote(c, "")
	}
	_, params, query, fragment := r.splitRequestURL()
	r.setPathParts("/"+strings.Join(quoted, "/"), params, query, fragment)
}

// Cookies returns the cookies of all Cookie headers, in order.
func (r *Request) Cookies() []CookiePair {
	return ParseCookieHeaders(r.Headers.GetAll("Cookie"))
}

// SetCookies replaces the Cookie headers with one header holding pairs.
func (r *Request) SetCookies(pairs []CookiePair) {
	r.Headers.Set("cookie", FormatCookieHeader(pairs))
}

// URLEncodedForm returns the fields of an application/x-www-form-urlencoded
// body. It returns nil when the Content-Type says the body is something
// else.
func (r *Request) URLEncodedForm() [][2]string {
	if !strings.Contains(strings.ToLower(r.Headers.Get("content-type")), "application/x-www-form-urlencoded") {
		return nil
	}
	return DecodeQuery(r.TextOrRaw())
}

// SetURLEncodedForm replaces the body with the form fields and sets the
// Content-Type to application/x-www-form-urlencoded. Fields with empty
// values follow the style of the existing body.
func (r *Request) SetURLEncodedForm(pairs [][2]string) {
	r.Headers.Set("content-type", "application/x-www-form-urlencoded")
	r.SetContent([]byte(EncodeQuery(pairs, r.TextOrRaw())))
}

// MultipartForm returns the parts of a multipart/form-data body as (name,
// value) pairs. It returns nil when the Content-Type says the body is
// something else or the body cannot be decoded.
func (r *Request) MultipartForm() [][2][]byte {
	ct := r.Headers.Get("content-type")
	if !strings.Contains(strings.ToLower(ct), "multipart/form-data") {
		return nil
	}
	content, err := r.Content()
	if err != nil || content == nil {
		return nil
	}
	parts, err := DecodeMultipart(ct, content)
	if err != nil {
		return nil
	}
	return parts
}

// SetMultipartForm replaces the body with the parts encoded as
// multipart/form-data. Without a multipart/form-data Content-Type, one with
// a random boundary is set first.
func (r *Request) SetMultipartForm(parts [][2][]byte) error {
	ct := r.Headers.Get("content-type")
	if !strings.HasPrefix(strings.ToLower(ct), "multipart/form-data") {
		var b [16]byte
		_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error.
		ct = "multipart/form-data; boundary=" + strings.Repeat("-", 20) + hex.EncodeToString(b[:])
		r.Headers.Set("content-type", ct)
	}
	body, err := EncodeMultipart(ct, parts)
	if err != nil {
		return err
	}
	r.SetContent(body)
	return nil
}

// errBoundaryInValue is returned by EncodeMultipart when a part's value is
// the boundary delimiter itself.
var errBoundaryInValue = errors.New("boundary found in encoded string")

// EncodeMultipart encodes parts as a multipart/form-data body using the
// boundary of contentType, as upstream's encode_multipart does. It returns
// an empty body when contentType has no boundary.
//
// Every part is labelled "text/plain; charset=utf-8": upstream guesses the
// type from the repr of the bytes name, which never carries a recognised
// extension.
func EncodeMultipart(contentType string, parts [][2][]byte) ([]byte, error) {
	ct, ok := parseContentType(contentType)
	if contentType == "" || !ok {
		return []byte{}, nil
	}
	raw, ok := ct.param("boundary")
	if !ok || !isASCII(raw) {
		return []byte{}, nil
	}
	boundary := []byte(Quote(raw, "/"))
	delim := append([]byte("--"), boundary...)
	var lines [][]byte
	for _, p := range parts {
		key, value := p[0], p[1]
		if len(key) > 0 {
			lines = append(lines,
				delim,
				append([]byte(`Content-Disposition: form-data; name="`), append(key, '"')...),
				[]byte("Content-Type: text/plain; charset=utf-8"),
				nil,
				value,
			)
		}
		lines = append(lines, nil)
		if value != nil && (bytes.Equal(value, delim) || bytes.Equal(value, append(delim, '\n'))) {
			return nil, errBoundaryInValue
		}
	}
	lines = append(lines, append(delim, "--\r\n"...))
	return bytes.Join(lines, []byte("\r\n")), nil
}

var multipartNameRE = regexp.MustCompile(`\bname="([^"]+)"`)

// errMultipart is returned by DecodeMultipart for a part without the blank
// line that ends its headers.
var errMultipart = errors.New("multipart part has no end of headers")

// DecodeMultipart extracts (name, value) pairs from a multipart/form-data
// body, with upstream's line-based algorithm: line breaks inside a value
// are dropped. It returns nil when contentType has no boundary.
func DecodeMultipart(contentType string, content []byte) ([][2][]byte, error) {
	if contentType == "" {
		return nil, nil
	}
	ct, ok := parseContentType(contentType)
	if !ok {
		return nil, nil
	}
	boundary, ok := ct.param("boundary")
	if !ok || !isASCII(boundary) {
		return nil, nil
	}
	var out [][2][]byte
	for chunk := range bytes.SplitSeq(content, []byte("--"+boundary)) {
		lines := splitLines(chunk)
		if len(lines) <= 1 || bytes.HasPrefix(lines[0], []byte("--")) {
			continue
		}
		m := multipartNameRE.FindSubmatch(lines[1])
		if m == nil {
			continue
		}
		blank := -1
		for i, l := range lines[2:] {
			if len(l) == 0 {
				blank = i
				break
			}
		}
		if blank < 0 {
			return nil, errMultipart
		}
		out = append(out, [2][]byte{m[1], bytes.Join(lines[3+blank:], nil)})
	}
	return out, nil
}

// splitLines splits b at "\n", "\r\n" and "\r", as Python's
// bytes.splitlines does, dropping a final empty line.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexAny(b, "\r\n")
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i])
		if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
			i++
		}
		b = b[i+1:]
	}
	return out
}

// Cookies returns the cookies of all Set-Cookie headers, in order.
func (r *Response) Cookies() []SetCookie {
	return ParseSetCookieHeaders(r.Headers.GetAll("set-cookie"))
}

// SetCookies replaces the Set-Cookie headers with one header per cookie.
func (r *Response) SetCookies(cookies []SetCookie) {
	values := make([]string, len(cookies))
	for i, c := range cookies {
		values[i] = FormatSetCookieHeader([]SetCookie{c})
	}
	r.Headers.SetAll("set-cookie", values)
}

// Refresh adjusts a response for replay at time now: the Date, Expires and
// Last-Modified headers and cookie expiry move forward by the time elapsed
// since the response started. A zero now means the current time.
func (r *Response) Refresh(now float64) {
	if now == 0 {
		now = stateutil.Now()
	}
	delta := now - r.TimestampStart
	for _, h := range []string{"date", "expires", "last-modified"} {
		v, ok := r.Headers.Lookup(h)
		if !ok {
			continue
		}
		if ts, ok := parseHTTPDate(v); ok {
			r.Headers.Set(h, formatHTTPDate(float64(ts)+delta))
		}
	}
	var refreshed []string
	for _, c := range r.Headers.GetAll("set-cookie") {
		v, err := RefreshSetCookieHeader(c, delta)
		if err != nil {
			v = c
		}
		refreshed = append(refreshed, v)
	}
	if len(refreshed) > 0 {
		r.Headers.SetAll("set-cookie", refreshed)
	}
}
