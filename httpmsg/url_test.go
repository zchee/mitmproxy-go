// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"testing"
)

func TestParseURL(t *testing.T) {
	t.Parallel()

	// Ports test/mitmproxy/net/http/test_url.py::test_parse and friends.
	tests := map[string]struct {
		in      string
		scheme  string
		host    string
		port    int
		path    string
		wantErr bool
	}{
		"success: explicit port":       {in: "http://foo.com:8888/test", scheme: "http", host: "foo.com", port: 8888, path: "/test"},
		"success: default http port":   {in: "http://foo/bar", scheme: "http", host: "foo", port: 80, path: "/bar"},
		"success: userinfo dropped":    {in: "http://user:pass@foo/bar", scheme: "http", host: "foo", port: 80, path: "/bar"},
		"success: empty path":          {in: "http://foo", scheme: "http", host: "foo", port: 80, path: "/"},
		"success: default https port":  {in: "https://foo", scheme: "https", host: "foo", port: 443, path: "/"},
		"success: host lower-cased":    {in: "HTTP://FOO.com/a", scheme: "http", host: "foo.com", port: 80, path: "/a"},
		"success: query and fragment":  {in: "http://foo/a;p?q=1#f", scheme: "http", host: "foo", port: 80, path: "/a;p?q=1#f"},
		"success: empty query dropped": {in: "http://foo/a?", scheme: "http", host: "foo", port: 80, path: "/a"},
		"success: ipv6":                {in: "http://[::1]:8080/", scheme: "http", host: "::1", port: 8080, path: "/"},
		"success: port zero defaults":  {in: "https://foo:0/", scheme: "https", host: "foo", port: 443, path: "/"},
		"error: empty":                 {in: "", wantErr: true},
		"error: no host":               {in: "not-a-url", wantErr: true},
		"error: non-numeric port":      {in: "https://foo:bar", wantErr: true},
		"error: non-ascii host":        {in: "http://\u00fafoo", wantErr: true},
		"error: non-ascii query":       {in: "http://foo/?a=\u00fa", wantErr: true},
		"error: invalid utf-8 host":    {in: "http://\xfafoo", wantErr: true},
		"error: invalid path":          {in: "http:/Æ/localhost:56121", wantErr: true},
		"error: null byte in host":     {in: "http://foo\x00", wantErr: true},
		"error: unbalanced bracket":    {in: "http://lo[calhost", wantErr: true},
		"error: port out of range":     {in: "http://foo:999999", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			scheme, host, port, path, err := ParseURL(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseURL(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if scheme != tt.scheme || host != tt.host || port != tt.port || path != tt.path {
				t.Errorf("ParseURL(%q) = (%q, %q, %d, %q), want (%q, %q, %d, %q)",
					tt.in, scheme, host, port, path, tt.scheme, tt.host, tt.port, tt.path)
			}
		})
	}
}

func TestParseURLBytes(t *testing.T) {
	t.Parallel()

	// Ports test_url.py::test_ascii_check.
	tests := map[string]struct {
		in      string
		path    string
		wantErr bool
	}{
		"success: utf-8 query is quoted": {
			in:   "https://xyz.tax-edu.net?flag=selectCourse&lc_id=42825&lc_name=茅莽莽猫氓猫氓",
			path: "/?flag%3DselectCourse%26lc_id%3D42825%26lc_name%3D%E8%8C%85%E8%8E%BD%E8%8E%BD%E7%8C%AB%E6%B0%93%E7%8C%AB%E6%B0%93",
		},
		"success: ascii unchanged": {in: "http://foo.com:8888/test?a=b", path: "/test?a=b"},
		"error: invalid utf-8":     {in: "http://foo/?\xff", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, _, path, err := ParseURLBytes([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseURLBytes(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if path != tt.path {
				t.Errorf("path = %q, want %q", path, tt.path)
			}
		})
	}
}

func TestUnparseURL(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		scheme, host string
		port         int
		path, want   string
	}{
		"success: non-default port": {scheme: "http", host: "foo.com", port: 99, want: "http://foo.com:99"},
		"success: default port":     {scheme: "http", host: "foo.com", port: 80, path: "/bar", want: "http://foo.com/bar"},
		"success: https port 80":    {scheme: "https", host: "foo.com", port: 80, want: "https://foo.com:80"},
		"success: https default":    {scheme: "https", host: "foo.com", port: 443, want: "https://foo.com"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := UnparseURL(tt.scheme, tt.host, tt.port, tt.path); got != tt.want {
				t.Errorf("UnparseURL = %q, want %q", got, tt.want)
			}
		})
	}
	if got := HostPort("https", "foo.com", 8080); got != "foo.com:8080" {
		t.Errorf("HostPort = %q", got)
	}
	if _, ok := DefaultPort("qux"); ok {
		t.Error("DefaultPort(qux) reported a port")
	}
}

func TestParseAuthority(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in       string
		valid    bool
		wantHost string
		wantPort int
	}{
		"success: host and port": {in: "foo:42", valid: true, wantHost: "foo", wantPort: 42},
		"success: ipv4":          {in: "127.0.0.1:443", valid: true, wantHost: "127.0.0.1", wantPort: 443},
		"success: ipv6":          {in: "[2001:db8:42::]:443", valid: true, wantHost: "2001:db8:42::", wantPort: 443},
		"success: host only":     {in: "foo", valid: true, wantHost: "foo", wantPort: -1},
		"success: punycode kept": {in: "xn--aaa-pla.example:80", valid: true, wantHost: "xn--aaa-pla.example", wantPort: 80},
		"error: empty label":     {in: "foo..bar", wantHost: "foo..bar", wantPort: -1},
		"error: port not digits": {in: "foo:bar", wantHost: "foo:bar", wantPort: -1},
		"error: port too large":  {in: "foo:999999999", wantHost: "foo:999999999", wantPort: -1},
		"error: invalid utf-8":   {in: "\xff", wantHost: "\xff", wantPort: -1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			host, port, err := ParseAuthority(tt.in, false)
			if err != nil || host != tt.wantHost || port != tt.wantPort {
				t.Errorf("ParseAuthority(%q, false) = (%q, %d, %v), want (%q, %d, nil)", tt.in, host, port, err, tt.wantHost, tt.wantPort)
			}
			_, _, err = ParseAuthority(tt.in, true)
			if (err == nil) != tt.valid {
				t.Errorf("ParseAuthority(%q, true) error = %v, want valid=%v", tt.in, err, tt.valid)
			}
		})
	}
}

func TestQuote(t *testing.T) {
	t.Parallel()

	// Every byte except '~', as upstream's surrogate test uses.
	var all []byte
	for b := range 256 {
		if b != '~' {
			all = append(all, byte(b))
		}
	}
	const allQuoted = "%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F" +
		"%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F" +
		"%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-./" +
		"0123456789%3A%3B%3C%3D%3E%3F%40" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"%5B%5C%5D%5E_%60" +
		"abcdefghijklmnopqrstuvwxyz" +
		"%7B%7C%7D%7F" +
		"%80%81%82%83%84%85%86%87%88%89%8A%8B%8C%8D%8E%8F" +
		"%90%91%92%93%94%95%96%97%98%99%9A%9B%9C%9D%9E%9F" +
		"%A0%A1%A2%A3%A4%A5%A6%A7%A8%A9%AA%AB%AC%AD%AE%AF" +
		"%B0%B1%B2%B3%B4%B5%B6%B7%B8%B9%BA%BB%BC%BD%BE%BF" +
		"%C0%C1%C2%C3%C4%C5%C6%C7%C8%C9%CA%CB%CC%CD%CE%CF" +
		"%D0%D1%D2%D3%D4%D5%D6%D7%D8%D9%DA%DB%DC%DD%DE%DF" +
		"%E0%E1%E2%E3%E4%E5%E6%E7%E8%E9%EA%EB%EC%ED%EE%EF" +
		"%F0%F1%F2%F3%F4%F5%F6%F7%F8%F9%FA%FB%FC%FD%FE%FF"

	tests := map[string]struct {
		raw, quoted string
	}{
		"success: plain":     {raw: "foo", quoted: "foo"},
		"success: space":     {raw: "foo bar", quoted: "foo%20bar"},
		"success: all bytes": {raw: string(all), quoted: allQuoted},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := Quote(tt.raw, "/"); got != tt.quoted {
				t.Errorf("Quote = %q, want %q", got, tt.quoted)
			}
			if got := Unquote(tt.quoted); got != tt.raw {
				t.Errorf("Unquote = %q, want %q", got, tt.raw)
			}
		})
	}
	if got := Unquote("%zz%4"); got != "%zz%4" {
		t.Errorf("Unquote kept malformed escapes as %q", got)
	}
}
