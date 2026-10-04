// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/flow/state"
)

// Cookie handling follows upstream's deliberately permissive parser: it
// keeps duplicate and malformed cookies, accepts the RFC 6265 formats and
// parts of RFC 2109 and RFC 2965, and reads the comma-separated variant of
// Set-Cookie that sets several cookies in one header. Values are escaped
// and quoted on output where needed, but data that violates the specs is
// never rejected.

// CookiePair is one name=value pair of a Cookie header. A pair without
// "=" has an empty value.
type CookiePair struct {
	Name  string
	Value string
}

// CookieAttr is one attribute of a Set-Cookie header. Value is nil for a
// unary attribute such as HttpOnly.
type CookieAttr struct {
	Name  string
	Value *string
}

// CookieAttrs are the attributes of one cookie, in order.
type CookieAttrs []CookieAttr

// Lookup returns the value of the named attribute, compared
// case-insensitively. When the attribute repeats, the last occurrence
// wins, as upstream decides.
func (a CookieAttrs) Lookup(name string) (value *string, ok bool) {
	for _, attr := range a {
		if strings.EqualFold(attr.Name, name) {
			value, ok = attr.Value, true
		}
	}
	return value, ok
}

// Has reports whether the named attribute is present.
func (a CookieAttrs) Has(name string) bool {
	_, ok := a.Lookup(name)
	return ok
}

// SetAll replaces the values of the named attribute the way
// [Headers.SetAll] does for headers.
func (a *CookieAttrs) SetAll(name string, values []*string) {
	out := make(CookieAttrs, 0, len(*a)+len(values))
	for _, attr := range *a {
		if !strings.EqualFold(attr.Name, name) {
			out = append(out, attr)
			continue
		}
		if len(values) > 0 {
			out = append(out, CookieAttr{Name: attr.Name, Value: values[0]})
			values = values[1:]
		}
	}
	for _, v := range values {
		out = append(out, CookieAttr{Name: name, Value: v})
	}
	*a = out
}

// Del removes every occurrence of the named attribute.
func (a *CookieAttrs) Del(name string) {
	out := (*a)[:0]
	for _, attr := range *a {
		if !strings.EqualFold(attr.Name, name) {
			out = append(out, attr)
		}
	}
	*a = out
}

// SetCookie is one cookie of a Set-Cookie header. Value is nil when the
// cookie has no "=".
type SetCookie struct {
	Name  string
	Value *string
	Attrs CookieAttrs
}

// readUntil reads from start up to the first byte in term.
func readUntil(s string, start int, term string) (string, int) {
	if start == len(s) {
		return "", start + 1
	}
	if i := strings.IndexAny(s[start:], term); i >= 0 {
		return s[start : start+i], start + i
	}
	return s[start:], len(s)
}

// readQuotedString reads the quoted string whose opening quote is at start,
// treating a backslash as an escape for the next byte.
func readQuotedString(s string, start int) (string, int) {
	var b strings.Builder
	escaping := false
	i := start
	for i = start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		case escaping:
			b.WriteByte(c)
			escaping = false
		case c == '"':
			return b.String(), i + 1
		case c == '\\':
			escaping = true
		default:
			b.WriteByte(c)
		}
	}
	// No closing quote: i ran to len(s), or the loop did not run.
	if start+1 >= len(s) {
		return "", start + 1
	}
	return b.String(), len(s)
}

func readKey(s string, start int, delims string) (string, int) {
	return readUntil(s, start, delims)
}

func readValue(s string, start int, delims string) (string, int) {
	switch {
	case start >= len(s):
		return "", start
	case s[start] == '"':
		return readQuotedString(s, start)
	}
	return readUntil(s, start, delims)
}

// readCookiePairs reads the name=value pairs of a Cookie header.
func readCookiePairs(s string) []CookiePair {
	var pairs []CookiePair
	off := 0
	for {
		var lhs, rhs string
		lhs, off = readKey(s, off, ";=")
		lhs = strings.TrimLeft(lhs, " \t\n\r\x0b\x0c")
		if off < len(s) && s[off] == '=' {
			rhs, off = readValue(s, off+1, ";")
		}
		if rhs != "" || lhs != "" {
			pairs = append(pairs, CookiePair{Name: lhs, Value: rhs})
		}
		off++
		if off >= len(s) {
			return pairs
		}
	}
}

// readSetCookiePairs reads the pairs of a Set-Cookie header, starting a new
// cookie at each top-level comma.
func readSetCookiePairs(s string) [][]CookieAttr {
	var cookies [][]CookieAttr
	var pairs []CookieAttr
	off := 0
	for {
		var lhs string
		lhs, off = readKey(s, off, ";=,")
		lhs = strings.TrimLeft(lhs, " \t\n\r\x0b\x0c")
		if off < len(s) && s[off] == '=' {
			var rhs string
			rhs, off = readValue(s, off+1, ";,")
			// Expires values contain a comma. A value of three bytes or
			// fewer ("Mon") means only the weekday was read, so read on.
			if strings.ToLower(lhs) == "expires" && len(rhs) <= 3 {
				var trail string
				trail, off = readValue(s, off+1, ";,")
				rhs = rhs + "," + trail
			}
			pairs = append(pairs, CookieAttr{Name: lhs, Value: &rhs})
		} else if lhs != "" {
			pairs = append(pairs, CookieAttr{Name: lhs})
		}
		if off < len(s) && s[off] == ',' {
			cookies = append(cookies, pairs)
			pairs = nil
		}
		off++
		if off >= len(s) {
			break
		}
	}
	if len(pairs) > 0 || len(cookies) == 0 {
		cookies = append(cookies, pairs)
	}
	return cookies
}

// hasSpecial reports whether a cookie value must be quoted.
func hasSpecial(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c == '"' || c == ',' || c == ';' || c == '\\' || c < 0x21 || c > 0x7e {
			return true
		}
	}
	return false
}

// formatPair formats one pair, quoting the value unless the lower-cased
// name is in noQuote.
func formatPair(b *strings.Builder, name string, value *string, noQuote ...string) {
	b.WriteString(name)
	if value == nil {
		return
	}
	b.WriteByte('=')
	v := *value
	quote := hasSpecial(v)
	for _, n := range noQuote {
		if strings.ToLower(name) == n {
			quote = false
		}
	}
	if !quote {
		b.WriteString(v)
		return
	}
	b.WriteByte('"')
	for i := range len(v) {
		if v[i] == '"' || v[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	b.WriteByte('"')
}

// ParseCookieHeader parses a Cookie header value into its pairs.
func ParseCookieHeader(line string) []CookiePair {
	return readCookiePairs(line)
}

// ParseCookieHeaders parses several Cookie header values into one list.
func ParseCookieHeaders(lines []string) []CookiePair {
	var out []CookiePair
	for _, l := range lines {
		out = append(out, ParseCookieHeader(l)...)
	}
	return out
}

// FormatCookieHeader formats pairs as a Cookie header value, quoting values
// that need it.
func FormatCookieHeader(pairs []CookiePair) string {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteString("; ")
		}
		formatPair(&b, p.Name, &p.Value)
	}
	return b.String()
}

// ParseSetCookieHeader parses a Set-Cookie header value. Attribute values
// are kept as strings, unparsed.
func ParseSetCookieHeader(line string) []SetCookie {
	var out []SetCookie
	for _, pairs := range readSetCookiePairs(line) {
		if len(pairs) == 0 {
			continue
		}
		out = append(out, SetCookie{Name: pairs[0].Name, Value: pairs[0].Value, Attrs: CookieAttrs(pairs[1:])})
	}
	return out
}

// ParseSetCookieHeaders parses several Set-Cookie header values into one
// list.
func ParseSetCookieHeaders(lines []string) []SetCookie {
	var out []SetCookie
	for _, l := range lines {
		out = append(out, ParseSetCookieHeader(l)...)
	}
	return out
}

// FormatSetCookieHeader formats cookies as one Set-Cookie header value,
// joining several cookies with ", ". Expires and Path values are never
// quoted.
func FormatSetCookieHeader(cookies []SetCookie) string {
	var b strings.Builder
	for i, c := range cookies {
		if i > 0 {
			b.WriteString(", ")
		}
		formatPair(&b, c.Name, c.Value, "expires", "path")
		for _, a := range c.Attrs {
			b.WriteString("; ")
			formatPair(&b, a.Name, a.Value, "expires", "path")
		}
	}
	return b.String()
}

// errInvalidCookie is returned by RefreshSetCookieHeader for a cookie
// without a name or value.
var errInvalidCookie = errors.New("invalid cookie")

// RefreshSetCookieHeader shifts the Expires attribute of every cookie in a
// Set-Cookie header value by delta seconds. An Expires value that cannot be
// parsed is removed. It fails for a cookie with an empty name or value.
func RefreshSetCookieHeader(c string, delta float64) (string, error) {
	cookies := ParseSetCookieHeader(c)
	for i := range cookies {
		ck := &cookies[i]
		if ck.Name == "" || ck.Value == nil || *ck.Value == "" {
			return "", errInvalidCookie
		}
		v, ok := ck.Attrs.Lookup("expires")
		if !ok {
			continue
		}
		var ts int64
		parsed := false
		if v != nil {
			ts, parsed = parseHTTPDate(*v)
		}
		if parsed {
			formatted := formatHTTPDate(float64(ts) + delta)
			ck.Attrs.SetAll("expires", []*string{&formatted})
		} else {
			ck.Attrs.Del("expires")
		}
	}
	return FormatSetCookieHeader(cookies), nil
}

// CookieExpiration returns when a cookie with the given attributes
// expires, from Expires or, without Expires, Max-Age. It reports false when
// neither yields a time. An unparsable Expires does not fall back to
// Max-Age, as upstream behaves.
func CookieExpiration(attrs CookieAttrs) (float64, bool) {
	if v, ok := attrs.Lookup("expires"); ok {
		if v != nil {
			if ts, ok := parseHTTPDate(*v); ok {
				return float64(ts), true
			}
		}
		return 0, false
	}
	if v, ok := attrs.Lookup("max-age"); ok && v != nil {
		maxAge, err := strconv.Atoi(strings.TrimSpace(*v))
		if err != nil {
			return 0, false
		}
		return state.Now() + float64(maxAge), true
	}
	return 0, false
}

// CookieExpired reports whether a cookie with the given attributes has
// expired. A cookie without expiration information never expires.
func CookieExpired(attrs CookieAttrs) bool {
	ts, ok := CookieExpiration(attrs)
	return ok && ts <= state.Now()
}

// cookieParams are the attribute names GroupCookies keeps with the
// preceding cookie.
var cookieParams = []string{"expires", "path", "comment", "max-age", "secure", "httponly", "version"}

// GroupCookies groups Cookie header pairs into cookies: a pair whose name
// is a cookie attribute (Path, Max-Age, ...) attaches to the cookie before
// it, and any other pair starts a new cookie.
func GroupCookies(pairs []CookiePair) []SetCookie {
	if len(pairs) == 0 {
		return nil
	}
	var out []SetCookie
	cur := SetCookie{Name: pairs[0].Name, Value: new(pairs[0].Value), Attrs: CookieAttrs{}}
	for _, p := range pairs[1:] {
		if slices.Contains(cookieParams, strings.ToLower(p.Name)) {
			cur.Attrs = append(cur.Attrs, CookieAttr{Name: p.Name, Value: new(p.Value)})
			continue
		}
		out = append(out, cur)
		cur = SetCookie{Name: p.Name, Value: new(p.Value), Attrs: CookieAttrs{}}
	}
	return append(out, cur)
}

var monthNames = []string{
	"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
	"january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december",
}

var dayNames = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

var tzOffsets = map[string]int{
	"UT": 0, "UTC": 0, "GMT": 0, "Z": 0,
	"AST": -400, "ADT": -300, "EST": -500, "EDT": -400,
	"CST": -600, "CDT": -500, "MST": -700, "MDT": -600,
	"PST": -800, "PDT": -700,
}

// pyInt parses an integer like Python's int(): surrounding whitespace and a
// sign are allowed.
func pyInt(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil
}

// parseHTTPDate parses a date the way Python's email.utils.parsedate_tz
// and mktime_tz do together, returning a Unix timestamp. It accepts RFC
// 5322 dates and the RFC 850 and cookie variants ("Thu, 01-Jan-1970
// 00:00:00 GMT"). A date without a known time zone is taken as UTC.
func parseHTTPDate(data string) (int64, bool) {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return 0, false
	}
	if strings.HasSuffix(fields[0], ",") || slices.Contains(dayNames, strings.ToLower(fields[0])) {
		fields = fields[1:]
	} else if i := strings.LastIndexByte(fields[0], ','); i >= 0 {
		fields[0] = fields[0][i+1:]
	}
	if len(fields) == 3 {
		if stuff := strings.Split(fields[0], "-"); len(stuff) == 3 {
			fields = append(stuff, fields[1:]...)
		}
	}
	if len(fields) == 4 {
		s := fields[3]
		i := strings.IndexByte(s, '+')
		if i == -1 {
			i = strings.IndexByte(s, '-')
		}
		if i > 0 {
			fields = append(fields[:3], s[:i], s[i:])
		} else {
			fields = append(fields, "")
		}
	}
	if len(fields) < 5 {
		return 0, false
	}
	dd, mm, yy, tm, tz := fields[0], fields[1], fields[2], fields[3], fields[4]
	if dd == "" || mm == "" || yy == "" {
		return 0, false
	}
	mm = strings.ToLower(mm)
	if !slices.Contains(monthNames, mm) {
		dd, mm = mm, strings.ToLower(dd)
		if !slices.Contains(monthNames, mm) {
			return 0, false
		}
	}
	month := slices.Index(monthNames, mm) + 1
	if month > 12 {
		month -= 12
	}
	dd = strings.TrimSuffix(dd, ",")
	if i := strings.IndexByte(yy, ':'); i > 0 {
		yy, tm = tm, yy
	}
	if strings.HasSuffix(yy, ",") {
		yy = yy[:len(yy)-1]
		if yy == "" {
			return 0, false
		}
	}
	if yy == "" || yy[0] < '0' || yy[0] > '9' {
		yy, tz = tz, yy
	}
	if tm == "" {
		return 0, false
	}
	tm = strings.TrimSuffix(tm, ",")
	parts := strings.Split(tm, ":")
	if len(parts) == 1 && strings.Contains(parts[0], ".") {
		parts = strings.Split(parts[0], ".")
	}
	var thh, tmm, tss string
	switch len(parts) {
	case 2:
		thh, tmm, tss = parts[0], parts[1], "0"
	case 3:
		thh, tmm, tss = parts[0], parts[1], parts[2]
	default:
		return 0, false
	}
	year, ok1 := pyInt(yy)
	day, ok2 := pyInt(dd)
	hour, ok3 := pyInt(thh)
	minute, ok4 := pyInt(tmm)
	sec, ok5 := pyInt(tss)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return 0, false
	}
	if year < 100 {
		if year > 68 {
			year += 1900
		} else {
			year += 2000
		}
	}
	offset := 0
	tz = strings.ToUpper(tz)
	if o, ok := tzOffsets[tz]; ok {
		offset = o
	} else if o, ok := pyInt(tz); ok {
		offset = o
	}
	if offset != 0 {
		sign := 1
		if offset < 0 {
			sign, offset = -1, -offset
		}
		offset = sign * ((offset/100)*3600 + (offset%100)*60)
	}
	t := time.Date(year, time.Month(month), day, hour, minute, sec, 0, time.UTC)
	return t.Unix() - int64(offset), true
}

// formatHTTPDate formats a Unix timestamp like Python's
// email.utils.formatdate(ts, usegmt=True), for example
// "Tue, 08 Mar 2011 00:21:38 GMT".
func formatHTTPDate(ts float64) string {
	return time.Unix(int64(ts), 0).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}
