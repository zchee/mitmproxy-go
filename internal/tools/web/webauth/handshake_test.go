// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/tools/web"
	"github.com/zchee/mitmproxy-go/options"
)

const handshakePassword = "handshake-cookie-test"

func composedWebMaster(t *testing.T) *web.Master {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir(), "server": false}); err != nil {
		t.Fatal(err)
	}
	m, err := web.New(t.Context(), web.Config{Options: opts, Stdin: io.NopCloser(strings.NewReader("")), Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return m
}

func handshakeRequest(t *testing.T, target *url.URL, jar http.CookieJar, authorization string) *http.Response {
	t.Helper()
	conn, err := new(net.Dialer).DialContext(t.Context(), "tcp", target.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	for _, cookie := range jar.Cookies(target) {
		r.AddCookie(cookie)
	}
	if err := r.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	jar.SetCookies(target, response.Cookies())
	return response
}

func cookieNamed(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	var found *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == name {
			if found != nil {
				t.Fatalf("duplicate cookie %s", name)
			}
			found = cookie
		}
	}
	if found == nil {
		t.Fatalf("cookie %s missing", name)
	}
	return found
}

func checkSessionCookie(t *testing.T, cookie *http.Cookie, before, after time.Time) {
	t.Helper()
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Secure {
		t.Fatalf("session cookie attributes = %#v", cookie)
	}
	if cookie.Expires.Before(before.Add(400*24*time.Hour).Truncate(time.Second)) || cookie.Expires.After(after.Add(400*24*time.Hour).Truncate(time.Second)) {
		t.Fatalf("session expiry %s is outside the measured 400-day window", cookie.Expires)
	}
}

func TestWebHandshakeCookies(t *testing.T) {
	m := composedWebMaster(t)
	server := httptest.NewServer(m.Handler())
	t.Cleanup(server.Close)
	port := server.Listener.Addr().(*net.TCPAddr).Port
	configured(t, m.Addons, m.Options, map[string]any{"web_password": handshakePassword, "web_port": port, "web_open_browser": false})
	cookieName := "mitmproxy-auth-" + strconv.Itoa(port)
	tests := map[string]struct {
		query, authorization string
		existing             bool
		want                 int
	}{
		"query_token":                 {query: handshakePassword, want: http.StatusSwitchingProtocols},
		"bearer_token":                {authorization: "Bearer " + handshakePassword, want: http.StatusSwitchingProtocols},
		"existing_cookie_precedence":  {query: "invalid", authorization: "Bearer invalid", existing: true, want: http.StatusSwitchingProtocols},
		"invalid_query_token":         {query: "invalid", want: http.StatusForbidden},
		"invalid_bearer_blocks_query": {query: handshakePassword, authorization: "Bearer invalid", want: http.StatusForbidden},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: server.Client().Transport, Jar: jar, Timeout: 30 * time.Second}
			t.Cleanup(client.CloseIdleConnections)
			var originalSession string
			if tt.existing {
				before := time.Now()
				r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/flows?token="+url.QueryEscape(handshakePassword), nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("session setup status = %d", response.StatusCode)
				}
				cookie := cookieNamed(t, response.Cookies(), cookieName)
				checkSessionCookie(t, cookie, before, time.Now())
				originalSession = cookie.Value
			}
			target, err := url.Parse(server.URL + "/updates")
			if err != nil {
				t.Fatal(err)
			}
			if tt.query != "" {
				target.RawQuery = url.Values{"token": {tt.query}}.Encode()
			}
			before := time.Now()
			response := handshakeRequest(t, target, jar, tt.authorization)
			if diff := gocmp.Diff(tt.want, response.StatusCode); diff != "" {
				t.Fatal(diff)
			}
			if tt.want == http.StatusSwitchingProtocols {
				if response.Header.Get("Upgrade") != "websocket" || response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
					t.Fatal("response did not complete the real WebSocket handshake")
				}
				if tt.existing {
					for _, cookie := range response.Cookies() {
						if cookie.Name == cookieName {
							t.Fatal("existing session was unexpectedly renewed")
						}
					}
				} else {
					checkSessionCookie(t, cookieNamed(t, response.Cookies(), cookieName), before, time.Now())
					if len(response.Header.Values("Set-Cookie")) != 2 {
						t.Fatal("real 101 did not forward both independent cookie headers")
					}
				}
				xsrf := cookieNamed(t, response.Cookies(), "_mitmproxy_xsrf")
				if xsrf.HttpOnly || xsrf.SameSite != http.SameSiteStrictMode || xsrf.Path != "/" || xsrf.Secure || !strings.HasPrefix(xsrf.Value, "2|") {
					t.Fatalf("XSRF cookie attributes = %#v", xsrf)
				}
				stored := cookieNamed(t, jar.Cookies(target), cookieName)
				if originalSession != "" && stored.Value != originalSession {
					t.Fatal("handshake replaced the existing session")
				}
				if cookieNamed(t, jar.Cookies(target), "_mitmproxy_xsrf").Value != xsrf.Value {
					t.Fatal("cookie jar did not capture the handshake XSRF cookie")
				}
			} else {
				for _, cookie := range jar.Cookies(target) {
					if strings.HasPrefix(cookie.Name, "mitmproxy-auth-") {
						t.Fatal("refused handshake created an authenticated session")
					}
				}
			}
			wantHTTP := http.StatusForbidden
			if tt.want == http.StatusSwitchingProtocols {
				wantHTTP = http.StatusOK
			}
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				path := "/flows"
				if method == http.MethodPost {
					path = "/clear"
				}
				r, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if method == http.MethodPost && tt.want == http.StatusSwitchingProtocols {
					r.Header.Set("X-XSRFToken", cookieNamed(t, jar.Cookies(target), "_mitmproxy_xsrf").Value)
					r.Header.Set("Sec-Fetch-Site", "same-origin")
				}
				if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
					t.Fatal("follow-up request must rely on cookie-jar authentication only")
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil {
					t.Fatalf("read/close response = %v, %v", readErr, closeErr)
				}
				if diff := gocmp.Diff(wantHTTP, response.StatusCode); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}
