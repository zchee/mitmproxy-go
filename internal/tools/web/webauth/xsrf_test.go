// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth

import (
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestWebXSRF(t *testing.T) {
	raw := []byte("0123456789abcdef")
	masked, err := maskXSRF(raw, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	remasked, err := maskXSRF(raw, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	other, err := maskXSRF([]byte("fedcba9876543210"), 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		cookie, input, header, body, query, requestedWith string
		want                                              int
	}{
		"missing":                           {cookie: masked, want: 403},
		"missing cookie":                    {input: masked, want: 403},
		"masked header":                     {cookie: masked, input: masked, want: 200},
		"different mask same token":         {cookie: masked, input: remasked, want: 200},
		"legacy hex cookie":                 {cookie: hex.EncodeToString(raw), input: masked, want: 200},
		"legacy hex input":                  {cookie: masked, input: hex.EncodeToString(raw), want: 200},
		"legacy text":                       {cookie: "legacy-token", input: "legacy-token", want: 200},
		"compatible header":                 {cookie: masked, input: remasked, header: "X-CSRFToken", want: 200},
		"form before header":                {cookie: masked, input: other, body: url.Values{"_xsrf": {remasked}}.Encode(), want: 200},
		"query before header":               {cookie: masked, input: other, query: url.Values{"_xsrf": {remasked}}.Encode(), want: 200},
		"body before query":                 {cookie: masked, body: url.Values{"_xsrf": {remasked}}.Encode(), query: url.Values{"_xsrf": {other}}.Encode(), want: 200},
		"empty form falls back to header":   {cookie: masked, input: remasked, body: "_xsrf=", want: 200},
		"form mismatch blocks valid header": {cookie: masked, input: remasked, body: url.Values{"_xsrf": {other}}.Encode(), want: 403},
		"last form argument":                {cookie: masked, body: url.Values{"_xsrf": {other, remasked}}.Encode(), want: 200},
		"mismatch":                          {cookie: masked, input: other, want: 403},
		"unknown version":                   {cookie: masked, input: "3|abcd|abcd|1700000000", want: 403},
		"invalid mask":                      {cookie: masked, input: "2|ff|abcd|1700000000", want: 403},
		"invalid timestamp":                 {cookie: masked, input: "2|00000000|abcd|huge", want: 403},
		"empty raw token":                   {cookie: masked, input: "2|00000000||1700000000", want: 403},
		"no requested-with bypass":          {cookie: masked, requestedWith: "XMLHttpRequest", want: 403},
		"bearer still requires xsrf":        {want: 403},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auth, _, _ := newAuth(t, "test")
			server := testServer(t, auth)
			headers := map[string]string{"Authorization": "Bearer test", "Content-Type": "application/x-www-form-urlencoded"}
			header := tt.header
			if header == "" {
				header = "X-XSRFToken"
			}
			headers[header] = tt.input
			headers["X-Requested-With"] = tt.requestedWith
			var cookies []*http.Cookie
			if tt.cookie != "" {
				cookies = append(cookies, &http.Cookie{Name: xsrfCookieName, Value: tt.cookie})
			}
			status, body, _ := request(t, server.Client(), "POST", server.URL+"/api?"+tt.query, tt.body, headers, cookies...)
			if diff := gocmp.Diff(tt.want, status); diff != "" {
				t.Fatal(diff)
			}
			if status == 403 {
				if diff := gocmp.Diff("<html><title>403: Forbidden</title><body>403: Forbidden</body></html>", body); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
	t.Run("upgrade_cookie_preparation", func(t *testing.T) {
		auth, _, _ := newAuth(t, "test")
		server := testServer(t, auth)
		status, _, cookies := request(t, server.Client(), "GET", server.URL+"/updates?token=test", "", nil)
		if status != 200 {
			t.Fatal(status)
		}
		findCookie(t, cookies, auth.AuthCookieName())
		xsrf := findCookie(t, cookies, xsrfCookieName)
		if xsrf.HttpOnly || xsrf.SameSite != http.SameSiteStrictMode {
			t.Fatal("XSRF cookie not readable/strict")
		}
		token, _, valid := decodeXSRF(xsrf.Value)
		if !valid || len(token) != 16 {
			t.Fatal("generated XSRF token invalid")
		}
		status, _, renewed := request(t, server.Client(), "GET", server.URL+"/updates", "", nil, cookies...)
		if status != 200 || len(renewed) != 0 {
			t.Fatalf("existing cookies status=%d renewed=%d", status, len(renewed))
		}
	})
	t.Run("decoded_comparison", func(t *testing.T) {
		first, _, ok := decodeXSRF(masked)
		second, _, otherOK := decodeXSRF(remasked)
		if !ok || !otherOK || subtle.ConstantTimeCompare(first, second) != 1 {
			t.Fatal("masking changed raw token")
		}
		if masked == remasked {
			t.Fatal("independent random masks repeated")
		}
	})
}

func TestWebFetchSite(t *testing.T) {
	tests := map[string]struct {
		method, site string
		present      bool
		want         int
	}{
		"same origin":    {"POST", "same-origin", true, 200},
		"none":           {"POST", "none", true, 200},
		"absent":         {"POST", "", false, 200},
		"empty present":  {"POST", "", true, 403},
		"cross site":     {"POST", "cross-site", true, 403},
		"same site":      {"PUT", "same-site", true, 403},
		"case sensitive": {"DELETE", "Same-Origin", true, 403},
		"safe get":       {"GET", "cross-site", true, 200},
		"safe head":      {"HEAD", "cross-site", true, 200},
		"safe options":   {"OPTIONS", "same-site", true, 200},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auth, _, _ := newAuth(t, "test")
			server := testServer(t, auth)
			xsrf, err := maskXSRF([]byte("0123456789abcdef"), 1700000000)
			if err != nil {
				t.Fatal(err)
			}
			headers := map[string]string{"Authorization": "Bearer test", "X-XSRFToken": xsrf}
			if tt.present {
				headers["Sec-Fetch-Site"] = tt.site
			}
			status, _, _ := request(t, server.Client(), tt.method, server.URL+"/api", "", headers, &http.Cookie{Name: xsrfCookieName, Value: xsrf})
			if diff := gocmp.Diff(tt.want, status); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestSignedCookie(t *testing.T) {
	tests := map[string]struct {
		name, value string
		want        bool
	}{
		"oracle vector":     {"mitmproxy-auth-8081", "2|1:0|10:1700000000|19:mitmproxy-auth-8081|4:eQ==|518d5bca11234a2ac01d69e5053b4235614acca5b837c311641e7c514886dd90", true},
		"overflow length":   {"mitmproxy-auth-8081", "2|184467440737095516160:0|", false},
		"missing separator": {"mitmproxy-auth-8081", "2|1:0", false},
		"unknown version":   {"mitmproxy-auth-8081", "3|1:0|", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			secret := []byte("test-only-cookie-key-material-32!!")
			at := time.Unix(1700000000, 0)
			if diff := gocmp.Diff(tt.want, validCookie(secret, tt.name, tt.value, at)); diff != "" {
				t.Fatal(diff)
			}
			if tt.want {
				if diff := gocmp.Diff(tt.value, signCookie(secret, tt.name, at)); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func FuzzWebAuthTokens(f *testing.F) {
	for _, value := range []string{"", "Bearer", "Bearer test", "2|1:0|10:1700000000|19:mitmproxy-auth-8081|4:eQ==|518d5bca11234a2ac01d69e5053b4235614acca5b837c311641e7c514886dd90", "2|00000000|30313233343536373839616263646566|1700000000", "1|legacy", "184467440737095516160:0", "\xff\x00"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 8192 {
			return
		}
		secret := []byte("nonsecret-fuzz-cookie-key")
		_ = validCookie(secret, "mitmproxy-auth-8081", value, time.Unix(1700000000, 0))
		token, timestamp, valid := decodeXSRF(value)
		if valid && len(token) > 0 {
			masked, err := maskXSRF(token, timestamp)
			if err != nil {
				t.Fatal(err)
			}
			decoded, gotTimestamp, valid := decodeXSRF(masked)
			if !valid || gotTimestamp != timestamp || !gocmp.Equal(token, decoded) {
				t.Fatal("XSRF round trip changed token")
			}
		}
		request := &http.Request{URL: &url.URL{RawQuery: "token=" + url.QueryEscape(value)}}
		_, _ = argument(request, "token")
		_, _, _ = strings.Cut(value, " ")
	})
}

func FuzzWebPasswordHash(f *testing.F) {
	for _, value := range []string{testHash, "$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$+mVW+bJM8rrFo4whr0C9Kg", "$argon2id$", "$argon2id$v=19$m=18446744073709551616,t=1,p=1$c2FsdHNhbHQ$ieVgG5ysTJFx4k/KvmC9aQ", strings.Repeat("$", 1025)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		hash, err := parsePasswordHash(value)
		if err != nil {
			return
		}
		if hash.memory < 8*uint32(hash.parallelism) || hash.memory > maxMemoryKiB || hash.time < 1 || hash.time > 10 || hash.parallelism < 1 || hash.parallelism > 16 || len(hash.salt) < 8 || len(hash.salt) > 64 || len(hash.digest) < 16 || len(hash.digest) > 64 || len(value) > 1024 {
			t.Fatal("accepted PHC outside fixed bounds")
		}
	})
}
