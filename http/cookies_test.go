// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http

import (
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func pairs(kv ...string) []CookiePair {
	out := make([]CookiePair, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		out = append(out, CookiePair{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

// attr builds a cookie attribute; a value of "\x00" means a unary
// attribute with no value.
func attr(name, value string) CookieAttr {
	if value == "\x00" {
		return CookieAttr{Name: name}
	}
	return CookieAttr{Name: name, Value: &value}
}

func TestReadKeyAndQuotedString(t *testing.T) {
	t.Parallel()

	// Ports test_cookies.py::test_read_key.
	keys := map[string]struct {
		s     string
		start int
		want  string
		off   int
	}{
		"success: whole":          {s: "foo", start: 0, want: "foo", off: 3},
		"success: offset":         {s: "foo", start: 1, want: "oo", off: 3},
		"success: leading space":  {s: " foo", start: 0, want: " foo", off: 4},
		"success: skip space":     {s: " foo", start: 1, want: "foo", off: 4},
		"success: stop at semi":   {s: " foo;", start: 1, want: "foo", off: 4},
		"success: stop at equals": {s: " foo=", start: 1, want: "foo", off: 4},
		"success: before value":   {s: " foo=bar", start: 1, want: "foo", off: 4},
	}
	for name, tt := range keys {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, off := readKey(tt.s, tt.start, ";=")
			if got != tt.want || off != tt.off {
				t.Errorf("readKey(%q, %d) = (%q, %d), want (%q, %d)", tt.s, tt.start, got, off, tt.want, tt.off)
			}
		})
	}

	// Ports test_cookies.py::test_read_quoted_string.
	quoted := map[string]struct {
		s     string
		start int
		want  string
		off   int
	}{
		"success: plain":          {s: `"foo" x`, start: 0, want: "foo", off: 5},
		"success: escaped letter": {s: `"f\oo" x`, start: 0, want: "foo", off: 6},
		"success: escaped slash":  {s: `"f\\o" x`, start: 0, want: `f\o`, off: 6},
		"success: trailing slash": {s: `"f\\" x`, start: 0, want: `f\`, off: 5},
		"success: escaped quote":  {s: `"fo\"" x`, start: 0, want: `fo"`, off: 6},
		"success: start past end": {s: `"foo" x`, start: 7, want: "", off: 8},
		"success: unterminated":   {s: `"abc`, start: 0, want: "abc", off: 4},
	}
	for name, tt := range quoted {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, off := readQuotedString(tt.s, tt.start)
			if got != tt.want || off != tt.off {
				t.Errorf("readQuotedString(%q, %d) = (%q, %d), want (%q, %d)", tt.s, tt.start, got, off, tt.want, tt.off)
			}
		})
	}
}

func TestCookieHeaderRoundTrip(t *testing.T) {
	t.Parallel()

	// Ports test_cookies.py::cookie_pairs, test_read_cookie_pairs and the
	// round-trip tests built on them.
	tests := map[string]struct {
		in   string
		want []CookiePair
	}{
		"success: empty name":           {in: "=uno", want: pairs("", "uno")},
		"success: empty header":         {in: "", want: nil},
		"success: single":               {in: "one=uno", want: pairs("one", "uno")},
		"success: name only":            {in: "one", want: pairs("one", "")},
		"success: empty value":          {in: "one=", want: pairs("one", "")},
		"success: two":                  {in: "one=uno; two=due", want: pairs("one", "uno", "two", "due")},
		"success: quoted with escape":   {in: `one="uno"; two="\due"`, want: pairs("one", "uno", "two", "due")},
		"success: escaped quote":        {in: `one="un\"o"`, want: pairs("one", `un"o`)},
		"success: comma inside quotes":  {in: `one="uno,due"`, want: pairs("one", "uno,due")},
		"success: bare middle cookie":   {in: "one=uno; two; three=tre", want: pairs("one", "uno", "two", "", "three", "tre")},
		"success: leading quote escape": {in: `one="\"two"; three=four`, want: pairs("one", `"two`, "three", "four")},
		"success: base64 values": {
			in:   "_lvs2=zHai1+Hq+Tc2vmc2r4GAbdOI5Jopg3EwsdUT9g=; _rcc2=53VdltWl+Ov6ordflA==;",
			want: pairs("_lvs2", "zHai1+Hq+Tc2vmc2r4GAbdOI5Jopg3EwsdUT9g=", "_rcc2", "53VdltWl+Ov6ordflA=="),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := ParseCookieHeader(tt.in)
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("ParseCookieHeader(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
			again := ParseCookieHeader(FormatCookieHeader(tt.want))
			if diff := gocmp.Diff(tt.want, again); diff != "" {
				t.Errorf("format round trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
	if got := FormatCookieHeader(pairs("a", `x"y`, "b", "c d")); got != `a="x\"y"; b="c d"` {
		t.Errorf("FormatCookieHeader quoting = %q", got)
	}
}

func TestSetCookiePairs(t *testing.T) {
	t.Parallel()

	// Ports test_cookies.py::test_parse_set_cookie_pairs.
	tests := map[string]struct {
		in   string
		want []CookieAttr
	}{
		"success: empty pair":      {in: "=", want: []CookieAttr{attr("", "")}},
		"success: empty then pair": {in: "=;foo=bar", want: []CookieAttr{attr("", ""), attr("foo", "bar")}},
		"success: two empties":     {in: "=;=;foo=bar", want: []CookieAttr{attr("", ""), attr("", ""), attr("foo", "bar")}},
		"success: empty name":      {in: "=uno", want: []CookieAttr{attr("", "uno")}},
		"success: single":          {in: "one=uno", want: []CookieAttr{attr("one", "uno")}},
		"success: trailing space":  {in: "one=un\x20", want: []CookieAttr{attr("one", "un\x20")}},
		"success: unary attribute": {in: "one=uno; foo", want: []CookieAttr{attr("one", "uno"), attr("foo", "\x00")}},
		"success: expires with comma": {
			in:   "mun=1.390.f60; expires=sun, 11-oct-2015 12:38:31 gmt; path=/; domain=b.aol.com",
			want: []CookieAttr{attr("mun", "1.390.f60"), attr("expires", "sun, 11-oct-2015 12:38:31 gmt"), attr("path", "/"), attr("domain", "b.aol.com")},
		},
		"success: escaped value": {
			in:   "rpb=190%3d1%2616726%3d1%2634832%3d1%2634874%3d1; domain=.rubiconproject.com; expires=mon, 11-may-2015 21:54:57 gmt; path=/",
			want: []CookieAttr{attr("rpb", "190%3d1%2616726%3d1%2634832%3d1%2634874%3d1"), attr("domain", ".rubiconproject.com"), attr("expires", "mon, 11-may-2015 21:54:57 gmt"), attr("path", "/")},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := readSetCookiePairs(tt.in)
			if diff := gocmp.Diff([][]CookieAttr{tt.want}, got); diff != "" {
				t.Fatalf("readSetCookiePairs(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
			c := SetCookie{Name: tt.want[0].Name, Value: tt.want[0].Value, Attrs: CookieAttrs(tt.want[1:])}
			again := readSetCookiePairs(FormatSetCookieHeader([]SetCookie{c}))
			if diff := gocmp.Diff([][]CookieAttr{tt.want}, again); diff != "" {
				t.Errorf("format round trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseSetCookieHeader(t *testing.T) {
	t.Parallel()

	sc := func(name, value string, attrs ...CookieAttr) SetCookie {
		if attrs == nil {
			attrs = CookieAttrs{}
		}
		return SetCookie{Name: name, Value: &value, Attrs: attrs}
	}
	// Ports test_cookies.py::test_parse_set_cookie_header.
	tests := map[string]struct {
		in   string
		want []SetCookie
	}{
		"success: empty":      {in: "", want: nil},
		"success: semicolon":  {in: ";", want: nil},
		"success: empty name": {in: "=uno", want: []SetCookie{sc("", "uno")}},
		"success: single":     {in: "one=uno", want: []SetCookie{sc("one", "uno")}},
		"success: attribute":  {in: "one=uno; foo=bar", want: []SetCookie{sc("one", "uno", attr("foo", "bar"))}},
		"success: repeated attribute": {
			in:   "one=uno; foo=bar; foo=baz",
			want: []SetCookie{sc("one", "uno", attr("foo", "bar"), attr("foo", "baz"))},
		},
		"success: comma separated": {
			in:   "foo=bar, doo=dar",
			want: []SetCookie{sc("foo", "bar"), sc("doo", "dar")},
		},
		"success: comma separated with attributes": {
			in:   "foo=bar; path=/, doo=dar; roo=rar; zoo=zar",
			want: []SetCookie{sc("foo", "bar", attr("path", "/")), sc("doo", "dar", attr("roo", "rar"), attr("zoo", "zar"))},
		},
		"success: expires without time": {
			in:   "foo=bar; expires=Mon, 24 Aug 2133",
			want: []SetCookie{sc("foo", "bar", attr("expires", "Mon, 24 Aug 2133"))},
		},
		"success: expires then next cookie": {
			in:   "foo=bar; expires=Mon, 24 Aug 2133 00:00:00 GMT, doo=dar",
			want: []SetCookie{sc("foo", "bar", attr("expires", "Mon, 24 Aug 2133 00:00:00 GMT")), sc("doo", "dar")},
		},
	}
	normalize := func(cs []SetCookie) []SetCookie {
		for i := range cs {
			if cs[i].Attrs == nil {
				cs[i].Attrs = CookieAttrs{}
			}
		}
		return cs
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := normalize(ParseSetCookieHeader(tt.in))
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("ParseSetCookieHeader(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
			if tt.want == nil {
				return
			}
			again := normalize(ParseSetCookieHeader(FormatSetCookieHeader(got)))
			if diff := gocmp.Diff(tt.want, again); diff != "" {
				t.Errorf("format round trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRefreshSetCookieHeader(t *testing.T) {
	t.Parallel()

	// Ports test_cookies.py::test_refresh_cookie.
	tests := map[string]struct {
		in       string
		delta    float64
		contains string
		absent   string
		wantErr  bool
	}{
		"success: four-digit year beyond 2038": {in: "rfoo=bar; Domain=reddit.com; expires=Thu, 31 Dec 2133 23:59:59 GMT; Path=/", delta: 60, contains: "Fri, 01 Jan 2134 00:00:59 GMT"},
		"success: dashed date":                 {in: "MOO=BAR; Expires=Tue, 08-Mar-2011 00:20:38 GMT; Path=foo.com; Secure", delta: 60, contains: "00:21:38"},
		"success: unparsable expires dropped":  {in: "rfoo=bar; Domain=reddit.com; expires=Thu, 31 Dec 2133; Path=/", delta: 60, absent: "expires"},
		"success: odd name":                    {in: ">=A", delta: 60, contains: ">=A"},
		"success: colon in name":               {in: "foo:bar=bla", contains: "foo:bar=bla"},
		"success: slash in name":               {in: "foo/bar=bla", contains: "foo/bar=bla"},
		"success: empty":                       {in: "", delta: 60},
		"error: cookie without value":          {in: "foo,bar", delta: 60, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := RefreshSetCookieHeader(tt.in, tt.delta)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RefreshSetCookieHeader(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Errorf("result %q does not contain %q", got, tt.contains)
			}
			if tt.absent != "" && strings.Contains(got, tt.absent) {
				t.Errorf("result %q contains %q", got, tt.absent)
			}
		})
	}
}

func TestParseHTTPDate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in     string
		want   int64
		wantOK bool
	}{
		"success: epoch with dashes": {in: "Thu, 01-Jan-1970 00:00:00 GMT", want: 0, wantOK: true},
		"success: far future":        {in: "Mon, 24-Aug-2133 00:00:00 GMT", want: 5164128000, wantOK: true},
		"success: rfc 5322 offset":   {in: "Tue, 08 Mar 2011 01:20:38 +0100", want: 1299543638, wantOK: true},
		"success: named zone":        {in: "Tue, 08 Mar 2011 19:20:38 EST", want: 1299630038, wantOK: true},
		"success: no weekday":        {in: "08 Mar 2011 00:20:38 GMT", want: 1299543638, wantOK: true},
		"success: two-digit year":    {in: "Tue, 08-Mar-11 00:20:38 GMT", want: 1299543638, wantOK: true},
		"success: asctime-like":      {in: "Wed Oct  21 16:29:41 2015", want: 1445444981, wantOK: true},
		"success: before 1970":       {in: "Mon, 01 Jan 1601 00:00:00 GMT", want: -11644473600, wantOK: true},
		"error: no time":             {in: "Thu, 31 Dec 2133", wantOK: false},
		"error: word":                {in: "false", wantOK: false},
		"error: empty":               {in: "", wantOK: false},
		"error: unknown month":       {in: "Thu, 01 Foo 1970 00:00:00 GMT", wantOK: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseHTTPDate(tt.in)
			if ok != tt.wantOK || (ok && got != tt.want) {
				t.Errorf("parseHTTPDate(%q) = (%d, %v), want (%d, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
	if got := formatHTTPDate(1299543698.9); got != "Tue, 08 Mar 2011 00:21:38 GMT" {
		t.Errorf("formatHTTPDate = %q", got)
	}
}

func TestCookieExpiry(t *testing.T) {
	t.Parallel()

	ca := func(kv ...string) CookieAttrs {
		var a CookieAttrs
		for i := 0; i < len(kv); i += 2 {
			a = append(a, attr(kv[i], kv[i+1]))
		}
		return a
	}
	// Ports test_cookies.py::test_get_expiration_ts and test_is_expired.
	if ts, ok := CookieExpiration(ca("Expires", "Thu, 01-Jan-1970 00:00:00 GMT")); !ok || ts != 0 {
		t.Errorf("epoch expiration = (%v, %v)", ts, ok)
	}
	if ts, ok := CookieExpiration(ca("Expires", "Mon, 24-Aug-2133 00:00:00 GMT")); !ok || ts != 5164128000 {
		t.Errorf("2133 expiration = (%v, %v)", ts, ok)
	}
	tests := map[string]struct {
		attrs CookieAttrs
		want  bool
	}{
		"success: expires in the past":     {attrs: ca("Expires", "Thu, 01-Jan-1970 00:00:00 GMT"), want: true},
		"success: max-age zero":            {attrs: ca("Max-Age", "0"), want: true},
		"success: both":                    {attrs: ca("Expires", "Thu, 01-Jan-1970 00:00:00 GMT", "Max-Age", "0"), want: true},
		"success: expires in the future":   {attrs: ca("Expires", "Mon, 24-Aug-2133 00:00:00 GMT"), want: false},
		"success: max-age positive":        {attrs: ca("Max-Age", "1"), want: false},
		"success: future expires wins":     {attrs: ca("Expires", "Wed, 15-Jul-2133 00:00:00 GMT", "Max-Age", "1"), want: false},
		"success: max-age not a number":    {attrs: ca("Max-Age", "nan"), want: false},
		"success: unparsable expires":      {attrs: ca("Expires", "false"), want: false},
		"success: no expiry information":   {attrs: nil, want: false},
		"success: last max-age value wins": {attrs: ca("max-age", "100", "Max-Age", "0"), want: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := CookieExpired(tt.attrs); got != tt.want {
				t.Errorf("CookieExpired(%v) = %v, want %v", tt.attrs, got, tt.want)
			}
		})
	}
}

func TestGroupCookies(t *testing.T) {
	t.Parallel()

	sc := func(name, value string, attrs ...CookieAttr) SetCookie {
		if attrs == nil {
			attrs = CookieAttrs{}
		}
		return SetCookie{Name: name, Value: &value, Attrs: attrs}
	}
	// Ports test_cookies.py::test_group_cookies.
	tests := map[string]struct {
		in   string
		want []SetCookie
	}{
		"success: all cookies": {
			in:   "one=uno; foo=bar; foo=baz",
			want: []SetCookie{sc("one", "uno"), sc("foo", "bar"), sc("foo", "baz")},
		},
		"success: attributes attach": {
			in:   "one=uno; Path=/; foo=bar; Max-Age=0; foo=baz; expires=24-08-1993",
			want: []SetCookie{sc("one", "uno", attr("Path", "/")), sc("foo", "bar", attr("Max-Age", "0")), sc("foo", "baz", attr("expires", "24-08-1993"))},
		},
		"success: trailing semicolon": {in: "one=uno;", want: []SetCookie{sc("one", "uno")}},
		"success: several attributes": {
			in:   "one=uno; Path=/; Max-Age=0; Expires=24-08-1993",
			want: []SetCookie{sc("one", "uno", attr("Path", "/"), attr("Max-Age", "0"), attr("Expires", "24-08-1993"))},
		},
		"success: attribute name first": {in: "path=val; Path=/", want: []SetCookie{sc("path", "val", attr("Path", "/"))}},
		"success: empty":                {in: "", want: nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, GroupCookies(ParseCookieHeader(tt.in))); diff != "" {
				t.Errorf("GroupCookies(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
		})
	}
}

func TestCookieAttrs(t *testing.T) {
	t.Parallel()

	a := CookieAttrs{attr("Path", "/"), attr("HttpOnly", "\x00"), attr("path", "/x")}
	if v, ok := a.Lookup("PATH"); !ok || *v != "/x" {
		t.Errorf("Lookup(PATH) = %v, %v; want the last value", v, ok)
	}
	if v, ok := a.Lookup("httponly"); !ok || v != nil {
		t.Errorf("Lookup(httponly) = %v, %v; want a unary attribute", v, ok)
	}
	a.SetAll("path", []*string{new("/y")})
	if diff := gocmp.Diff(CookieAttrs{attr("Path", "/y"), attr("HttpOnly", "\x00")}, a); diff != "" {
		t.Errorf("SetAll mismatch (-want +got):\n%s", diff)
	}
	a.Del("HTTPONLY")
	if a.Has("httponly") || len(a) != 1 {
		t.Errorf("Del left %v", a)
	}
}
