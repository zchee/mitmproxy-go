// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package check

import (
	"strings"
	"testing"
)

// TestIsValidHostBytes holds the cases of mitmproxy's test_check.py, which
// pass bytes, followed by edge cases whose expectations were taken from
// running upstream's is_valid_host on CPython 3.14.
func TestIsValidHostBytes(t *testing.T) {
	tests := map[string]struct {
		host string
		want bool
	}{
		"invalid: empty":                          {host: "", want: false},
		"invalid: punycode that fails":            {host: "xn--ke.ws", want: false},
		"valid: two labels":                       {host: "one.two", want: true},
		"invalid: longer than 255 bytes":          {host: strings.Repeat("one", 255), want: false},
		"valid: trailing dot":                     {host: "one.two.", want: true},
		"valid: underscore":                       {host: "one_two", want: true},
		"valid: IPv6 loopback":                    {host: "::1", want: true},
		"valid: IPv4":                             {host: "127.0.0.1", want: true},
		"valid: IPv6 full":                        {host: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", want: true},
		"valid: IPv6 short groups":                {host: "2001:db8:85a3:0:0:8a2e:370:7334", want: true},
		"valid: IPv6 compressed":                  {host: "2001:db8:85a3::8a2e:370:7334", want: true},
		"invalid: IPv6 with two ::":               {host: "2001:db8::85a3::7334", want: false},
		"valid: IPv6 literal DNS name":            {host: "2001-db8-85a3-8d3-1319-8a2e-370-7348.ipv6-literal.net", want: true},
		"valid: two-letter TLD":                   {host: "example.tl", want: true},
		"valid: three-letter TLD":                 {host: "example.tld", want: true},
		"valid: 63-byte TLD":                      {host: "example." + strings.Repeat("x", 63), want: true},
		"invalid: 64-byte TLD":                    {host: "example." + strings.Repeat("x", 64), want: false},
		"invalid: at sign":                        {host: "ex@mple", want: false},
		"invalid: at sign with TLD":               {host: "ex@mple.com", want: false},
		"invalid: empty label":                    {host: "example..com", want: false},
		"invalid: leading dot":                    {host: ".example.com", want: false},
		"invalid: at sign label":                  {host: "@.example.com", want: false},
		"invalid: exclamation label":              {host: "!.example.com", want: false},
		"invalid: only TLD after dot":             {host: ".tld", want: false},
		"valid: 1-byte label":                     {host: "x.tld", want: true},
		"valid: 30-byte label":                    {host: strings.Repeat("x", 30) + ".tld", want: true},
		"invalid: 64-byte label":                  {host: strings.Repeat("x", 64) + ".tld", want: false},
		"valid: 1-byte label, 3 labels":           {host: "x.example.tld", want: true},
		"valid: 30-byte label, 3 labels":          {host: strings.Repeat("x", 30) + ".example.tld", want: true},
		"invalid: 64-byte label, 3 labels":        {host: strings.Repeat("x", 64) + ".example.tld", want: false},
		"valid: leading underscore":               {host: "_example", want: true},
		"valid: surrounding underscores":          {host: "_example_", want: true},
		"valid: trailing underscore":              {host: "example_", want: true},
		"valid: underscore label start":           {host: "_a.example.tld", want: true},
		"valid: underscore label end":             {host: "a_.example.tld", want: true},
		"valid: underscore label both":            {host: "_a_.example.tld", want: true},
		"valid: leading hyphen":                   {host: "-example", want: true},
		"valid: hyphen and underscore":            {host: "-example_", want: true},
		"valid: trailing hyphen":                  {host: "example-", want: true},
		"valid: hyphen label start":               {host: "-a.example.tld", want: true},
		"valid: hyphen label end":                 {host: "a-.example.tld", want: true},
		"valid: hyphen label both":                {host: "-a-.example.tld", want: true},
		"valid: api-":                             {host: "api-.example.com", want: true},
		"valid: double underscore":                {host: "__a.example-site.com", want: true},
		"valid: underscore hyphen":                {host: "_-a.example-site.com", want: true},
		"valid: underscores around":               {host: "_a_.example-site.com", want: true},
		"valid: hyphens around":                   {host: "-a-.example-site.com", want: true},
		"valid: api- with subdomain":              {host: "api-.a.example.com", want: true},
		"valid: api- with _a":                     {host: "api-._a.example.com", want: true},
		"valid: api- with a_":                     {host: "api-.a_.example.com", want: true},
		"valid: api- with ab":                     {host: "api-.ab.example.com", want: true},
		"valid: IPv6 with zone":                   {host: "fe80::1%eth0", want: true},
		"valid: zone with unreserved punctuation": {host: "fe80::1%en0.1_a-b~c", want: true},
		"valid: zone with percent-encoding":       {host: "fe80::1%eth%2F0", want: true},
		"invalid: zone with slash traversal":      {host: "::1%a/../../secret", want: false},
		"invalid: zone with absolute path":        {host: "fe80::1%/tmp/x", want: false},
		"invalid: zone with backslash":            {host: "fe80::1%a\\b", want: false},
		"invalid: zone with NUL":                  {host: "fe80::1%a\x00", want: false},
		"invalid: zone with space":                {host: "fe80::1%a b", want: false},
		"invalid: zone with colon":                {host: "fe80::1%a:b", want: false},
		"invalid: zone with truncated escape":     {host: "fe80::1%a%4", want: false},
		"invalid: zone with non-hex escape":       {host: "fe80::1%a%zz", want: false},
		"invalid: empty zone":                     {host: "fe80::1%", want: false},
		"valid: IPv4 leading zero is a name":      {host: "01.2.3.4", want: true},
		"valid: IPv4-mapped IPv6":                 {host: "::ffff:1.2.3.4", want: true},
		"valid: IPv4 with trailing dot":           {host: "127.0.0.1.", want: true},
		"valid: IPv6 with trailing dot":           {host: "::1.", want: true},
		"invalid: bracketed IPv6":                 {host: "[::1]", want: false},
		"valid: punycode label":                   {host: "xn--mnchen-3ya.de", want: true},
		"valid: upper-case punycode label":        {host: "XN--MNCHEN-3YA.de", want: true},
		"invalid: punycode of a mapped character": {host: "xn--zca.de", want: false},
		"invalid: punycode of an ASCII label":     {host: "xn--ss-.de", want: false},
		"invalid: bare ACE prefix":                {host: "xn--", want: false},
		"invalid: non-ASCII bytes":                {host: "\xc3\xa9.com", want: false},
		"valid: punycode emoji label":             {host: "xn--e28h.com", want: true},
		"invalid: 64 bytes":                       {host: strings.Repeat("a", 64), want: false},
		"valid: 63-byte last label then dot":      {host: "a." + strings.Repeat("b", 63) + ".", want: true},
		// Upstream accepts this because Python's "$" also matches before a
		// final newline; the port does not.
		"invalid: trailing newline": {host: "example.com\n", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsValidHost([]byte(tt.host)); got != tt.want {
				t.Errorf("IsValidHost([]byte(%q)) = %t, want %t", tt.host, got, tt.want)
			}
		})
	}
}

// TestIsValidHostString covers the str path, which IDNA-encodes the host
// before checking it. Expectations come from upstream on CPython 3.14.
func TestIsValidHostString(t *testing.T) {
	tests := map[string]struct {
		host string
		want bool
	}{
		"valid: plain name":                      {host: "example.tld", want: true},
		"invalid: empty label cannot be encoded": {host: "foo..bar", want: false},
		"valid: IDN":                             {host: "münchen.de", want: true},
		"valid: upper-case IDN":                  {host: "MÜNCHEN.de", want: true},
		"valid: sharp s maps to ss":              {host: "ß.de", want: true},
		"valid: sharp s inside a label":          {host: "faß.de", want: true},
		"invalid: ACE prefix on non-ASCII":       {host: "xn--ü.de", want: false},
		"valid: ideographic full stop":           {host: "a。b", want: true},
		"valid: trailing ideographic full stop":  {host: "a。", want: true},
		"invalid: only an ideographic full stop": {host: "。", want: false},
		"invalid: empty":                         {host: "", want: false},
		"valid: 63-byte label then dot":          {host: strings.Repeat("a", 63) + ".", want: true},
		"valid: 63-byte last label":              {host: "a." + strings.Repeat("b", 63), want: true},
		"invalid: 64 bytes":                      {host: strings.Repeat("a", 64), want: false},
		"invalid: 64-byte first label":           {host: strings.Repeat("a", 64) + ".b", want: false},
		"invalid: 64-byte last label":            {host: "b." + strings.Repeat("a", 64), want: false},
		"valid: IPv6":                            {host: "::1", want: true},
		"invalid: character that maps to a dot":  {host: "⒈.com", want: false},
		"invalid: trailing newline":              {host: "abc\n", want: false},
		"valid: emoji label":                     {host: "\U0001F600.com", want: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsValidHost(tt.host); got != tt.want {
				t.Errorf("IsValidHost(%q) = %t, want %t", tt.host, got, tt.want)
			}
		})
	}
}

// TestIsValidHostZoneVariantsAgree pins that a string and a byte slice agree
// on IPv6 zones. A zone holds only RFC 6874 ZoneID characters, so a host
// that names a zone can never carry a path separator into a file name.
func TestIsValidHostZoneVariantsAgree(t *testing.T) {
	tests := map[string]struct {
		host string
		want bool
	}{
		"valid: interface name":            {host: "fe80::1%eth0", want: true},
		"valid: percent-encoded percent":   {host: "fe80::1%25eth0", want: true},
		"valid: dotted interface":          {host: "fe80::1%en0.1", want: true},
		"invalid: empty zone label":        {host: "fe80::1%..", want: false},
		"invalid: encoded empty label":     {host: "fe80::1%2f..%2fsecret", want: false},
		"invalid: long zone label":         {host: "fe80::1%" + strings.Repeat("x", 64), want: false},
		"invalid: absolute path":           {host: "fe80::1%/tmp/x", want: false},
		"invalid: parent path":             {host: "fe80::1%/../../x", want: false},
		"invalid: trailing parent":         {host: "fe80::1%x/..", want: false},
		"invalid: loopback traversal":      {host: "::1%a/../../b", want: false},
		"invalid: IPv4 with zone":          {host: "1.2.3.4%x", want: false},
		"invalid: backslash":               {host: "fe80::1%a\\b", want: false},
		"invalid: NUL":                     {host: "fe80::1%a\x00", want: false},
		"invalid: percent without escape":  {host: "fe80::1%a%", want: false},
		"invalid: second zone":             {host: "fe80::1%a%eth0", want: false},
		"invalid: non-ASCII zone":          {host: "fe80::1%\xc3\xa9", want: false},
		"invalid: newline after zone":      {host: "fe80::1%eth0\n", want: false},
		"invalid: zone on a plain name":    {host: "example.com%eth0", want: false},
		"invalid: zone with question mark": {host: "fe80::1%a?b", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			gotString, gotBytes := IsValidHost(tt.host), IsValidHost([]byte(tt.host))
			if gotString != tt.want || gotBytes != tt.want {
				t.Errorf("IsValidHost(%q): string=%t bytes=%t, want %t", tt.host, gotString, gotBytes, tt.want)
			}
		})
	}
}

func TestIsValidPort(t *testing.T) {
	tests := map[string]struct {
		port int
		want bool
	}{
		"valid: zero":         {port: 0, want: true},
		"valid: 443":          {port: 443, want: true},
		"valid: maximum":      {port: 65535, want: true},
		"invalid: negative":   {port: -1, want: false},
		"invalid: too large":  {port: 65536, want: false},
		"invalid: way beyond": {port: 999999, want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsValidPort(tt.port); got != tt.want {
				t.Errorf("IsValidPort(%d) = %t, want %t", tt.port, got, tt.want)
			}
		})
	}
}

func FuzzIsValidHost(f *testing.F) {
	for _, seed := range []string{"example.com", "xn--mnchen-3ya.de", "münchen.de", "::1", "127.0.0.1", "a。b", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		_ = IsValidHost(host)
		if !IsValidHost([]byte(host)) {
			return
		}
		if len(host) > maxHostLen {
			t.Fatalf("IsValidHost accepted %d bytes, more than %d", len(host), maxHostLen)
		}
		// A valid host is made of label characters, dots and the colons of an
		// IPv6 address; its zone adds only "~" and percent escapes, so no
		// path separator, NUL or other control byte can pass.
		for i := range len(host) {
			switch c := host[i]; {
			case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', strings.IndexByte("-_.:", c) >= 0:
			case (c == '~' || c == '%') && strings.Contains(host, "%"):
			default:
				t.Fatalf("IsValidHost accepted %q with byte %q", host, c)
			}
		}
	})
}
