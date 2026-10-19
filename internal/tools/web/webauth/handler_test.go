// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

const testHash = "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$ieVgG5ysTJFx4k/KvmC9aQ"

func newAuth(t *testing.T, password string) (*WebAuth, *addon.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	for name, value := range map[string]any{"web_port": 8081, "web_host": "127.0.0.1"} {
		typ := options.TypeStr
		if name == "web_port" {
			typ = options.TypeInt
		}
		if err := opts.Add(t.Context(), name, typ, value, "test web listener"); err != nil {
			t.Fatal(err)
		}
	}
	auth := New(opts)
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), auth); err != nil {
		t.Fatal(err)
	}
	updateAuth(t, manager, opts, map[string]any{"web_password": password})
	return auth, manager, opts
}

func updateAuth(t *testing.T, manager *addon.Manager, opts *options.Manager, values map[string]any) {
	t.Helper()
	if err := manager.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, values) }); err != nil {
		t.Fatal(err)
	}
}

func testLogin(w http.ResponseWriter, _ *http.Request, data LoginData) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusForbidden)
	heading := "Authentication required"
	if data.InvalidPassword {
		heading = "Invalid password"
	}
	_, _ = fmt.Fprintf(w, "<h1>%s</h1><input name=\"_xsrf\" value=\"%s\">", heading, data.XSRFToken)
}

func testServer(t *testing.T, auth *WebAuth) *httptest.Server {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "accepted") })
	mux := http.NewServeMux()
	mux.Handle("/", auth.Wrap(next, testLogin))
	mux.Handle("/api", auth.Wrap(next, nil))
	mux.HandleFunc("/updates", func(w http.ResponseWriter, r *http.Request) {
		if auth.PrepareUpgrade(w, r) {
			// This handler deliberately does not perform a handshake. The real
			// 101 integration belongs to the WebSocket consumer tests.
			w.WriteHeader(http.StatusOK)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func request(t *testing.T, client *http.Client, method, address, body string, headers map[string]string, cookies ...*http.Cookie) (int, string, []*http.Cookie) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, address, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(data), response.Cookies()
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %s not set", name)
	return nil
}

func TestWebAuthentication(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct {
			header string
			query  string
			path   string
			want   int
			port   bool
		}{
			"test_login_with_token_header":              {header: "Bearer test", want: 200},
			"test_login_with_token_param":               {query: "?token=test", want: 200},
			"test_login_with_malformed_auth_header":     {header: "Bearer", want: 403},
			"test_login_with_invalid_auth_header":       {header: "Bearer invalid_token", want: 403},
			"test_unauthorized_api":                     {want: 403},
			"test_unauthorized_websocket":               {path: "/updates", want: 403},
			"test_auth_cookie_port_suffix_modification": {query: "?token=test", want: 200, port: true},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				auth, manager, opts := newAuth(t, "test")
				if tt.port {
					updateAuth(t, manager, opts, map[string]any{"web_port": 8082})
					if diff := gocmp.Diff("mitmproxy-auth-8082", auth.AuthCookieName()); diff != "" {
						t.Fatal(diff)
					}
				}
				server := testServer(t, auth)
				path := tt.path
				if path == "" {
					path = "/"
				}
				status, _, cookies := request(t, server.Client(), "GET", server.URL+path+tt.query, "", map[string]string{"Authorization": tt.header})
				if diff := gocmp.Diff(tt.want, status); diff != "" {
					t.Fatal(diff)
				}
				if tt.want == 200 {
					findCookie(t, cookies, auth.AuthCookieName())
				}
			})
		}
	})
	t.Run("precedence", func(t *testing.T) {
		tests := map[string]struct {
			header, query string
			cookie        bool
			want          int
		}{
			"bad bearer blocks query":  {header: "Bearer wrong", query: "?token=test", want: 403},
			"empty bearer uses query":  {header: "Bearer ", query: "?token=test", want: 200},
			"bare bearer uses query":   {header: "Bearer", query: "?token=test", want: 200},
			"lowercase scheme ignored": {header: "bearer test", want: 403},
			"other scheme uses query":  {header: "Basic wrong", query: "?token=test", want: 200},
			"extra space not trimmed":  {header: "Bearer  test", query: "?token=test", want: 403},
			"last query argument":      {query: "?token=wrong&token=%20test%20", want: 200},
			"cookie before bad bearer": {header: "Bearer wrong", cookie: true, want: 200},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				auth, _, _ := newAuth(t, "test")
				server := testServer(t, auth)
				var cookies []*http.Cookie
				if tt.cookie {
					_, _, cookies = request(t, server.Client(), "GET", server.URL+"/?token=test", "", nil)
				}
				status, _, _ := request(t, server.Client(), "GET", server.URL+tt.query, "", map[string]string{"Authorization": tt.header}, cookies...)
				if diff := gocmp.Diff(tt.want, status); diff != "" {
					t.Fatal(diff)
				}
			})
		}
	})
	t.Run("sessions", func(t *testing.T) {
		tests := map[string]struct {
			age                   time.Duration
			tamper, wrongPort, v1 bool
			want                  int
		}{
			"valid":                          {want: 200},
			"thirty days":                    {age: 30 * 24 * time.Hour, want: 200},
			"thirty one day boundary":        {age: 31 * 24 * time.Hour, want: 200},
			"expired":                        {age: 31*24*time.Hour + time.Second, want: 403},
			"four hundred days not accepted": {age: 399 * 24 * time.Hour, want: 403},
			"tampered":                       {tamper: true, want: 403},
			"wrong port":                     {wrongPort: true, want: 403},
			"version one":                    {v1: true, want: 403},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				auth, _, _ := newAuth(t, "test")
				at := time.Unix(1700000000, 0)
				auth.clock = func() time.Time { return at }
				cookiePort := "mitmproxy-auth-8081"
				if tt.wrongPort {
					cookiePort = "mitmproxy-auth-8082"
				}
				value := signCookie(auth.secret[:], cookiePort, at.Add(-tt.age))
				if tt.tamper {
					value += "0"
				}
				if tt.v1 {
					value = "eQ==|1700000000|bad-signature"
				}
				server := testServer(t, auth)
				status, _, _ := request(t, server.Client(), "GET", server.URL+"/api", "", nil, &http.Cookie{Name: auth.AuthCookieName(), Value: value})
				if diff := gocmp.Diff(tt.want, status); diff != "" {
					t.Fatal(diff)
				}
			})
		}
	})
}

func TestWebLogin(t *testing.T) {
	tests := map[string]struct {
		query   string
		heading string
	}{
		"missing password": {heading: "Authentication required"},
		"wrong password":   {query: "?token=wrong", heading: "Invalid password"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auth, _, _ := newAuth(t, "test")
			server := testServer(t, auth)
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			client := server.Client()
			client.Jar = jar
			status, body, cookies := request(t, client, "GET", server.URL+tt.query, "", nil)
			if status != 403 || !strings.Contains(body, tt.heading) {
				t.Fatalf("status=%d body=%s", status, body)
			}
			xsrf := findCookie(t, cookies, xsrfCookieName)
			if xsrf.HttpOnly || xsrf.SameSite != http.SameSiteStrictMode || xsrf.Path != "/" {
				t.Fatalf("XSRF flags = %#v", xsrf)
			}
			form := url.Values{"token": {"wrong", "test"}, "_xsrf": {xsrf.Value}}
			status, _, cookies = request(t, client, "POST", server.URL+"/?token=wrong", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
			if status != 200 {
				t.Fatalf("login POST status=%d", status)
			}
			session := findCookie(t, cookies, auth.AuthCookieName())
			if !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" || session.Secure {
				t.Fatalf("session flags = %#v", session)
			}
			if duration := time.Until(session.Expires); duration < 399*24*time.Hour || duration > 401*24*time.Hour {
				t.Fatalf("session expiry offset = %v", duration)
			}
			status, _, cookies = request(t, client, "GET", server.URL+"/api", "", map[string]string{"Authorization": "Bearer wrong"})
			if status != 200 || len(cookies) != 0 {
				t.Fatalf("cookie login status=%d renewed=%d", status, len(cookies))
			}
		})
	}
	t.Run("resource_budget", func(t *testing.T) {
		auth, manager, opts := newAuth(t, testHash)
		server := testServer(t, auth)
		if err := reserveVerifier(t.Context(), 8); err != nil {
			t.Fatal(err)
		}
		if err := reserveVerifier(t.Context(), 8); err != nil {
			releaseVerifier(8)
			t.Fatal(err)
		}
		status, _, _ := request(t, server.Client(), "GET", server.URL+"/api?token=test", "", nil)
		if status != 503 {
			t.Errorf("concurrency exhaustion status=%d", status)
		}
		updateAuth(t, manager, opts, map[string]any{"web_password": "$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$+mVW+bJM8rrFo4whr0C9Kg"})
		other, _, _ := newAuth(t, testHash)
		for _, instance := range []*WebAuth{auth, other} {
			if _, err := instance.IsValidPassword(t.Context(), "test"); !errors.Is(err, ErrVerifierBusy) {
				t.Errorf("configuration or instance reset shared reservations: %v", err)
			}
		}
		releaseVerifier(8)
		releaseVerifier(8)
		if err := reserveVerifier(t.Context(), maxMemoryKiB); err != nil {
			t.Fatal(err)
		}
		status, _, _ = request(t, server.Client(), "GET", server.URL+"/api?token=test", "", nil)
		if status != 503 {
			t.Errorf("memory exhaustion status=%d", status)
		}
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		if err := reserveVerifier(canceled, 8); !errors.Is(err, context.Canceled) {
			t.Errorf("canceled acquisition = %v", err)
		}
		releaseVerifier(maxMemoryKiB)
		if _, err := auth.IsValidPassword(canceled, "test"); !errors.Is(err, context.Canceled) {
			t.Errorf("canceled verification with free budget = %v", err)
		}
		workingHash, err := parsePasswordHash(strings.Replace(testHash, "m=8,t=1", "m=32768,t=10", 1))
		if err != nil {
			t.Fatal(err)
		}
		derivationContext, cancelDerivation := context.WithCancel(t.Context())
		result := make(chan error, 1)
		finished := make(chan struct{})
		defer func() { cancelDerivation(); <-finished }()
		go func() {
			defer close(finished)
			_, err := workingHash.check(derivationContext, "test")
			result <- err
		}()
		watchdog := time.NewTimer(10 * time.Second)
		defer watchdog.Stop()
		for {
			verifierBudget.Lock()
			reserved := verifierBudget.active == 1 && verifierBudget.memory == workingHash.memory
			if reserved {
				cancelDerivation()
				// Cancellation cannot free a reservation while Argon2 still owns it.
				if verifierBudget.active != 1 || verifierBudget.memory != workingHash.memory {
					t.Error("cancellation released an active derivation")
				}
			}
			verifierBudget.Unlock()
			if reserved {
				break
			}
			select {
			case err := <-result:
				t.Fatalf("derivation finished before cancellation observation: %v", err)
			case <-watchdog.C:
				var stacks strings.Builder
				_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
				t.Fatalf("derivation did not reserve its budget\n%s", stacks.String())
			default:
				runtime.Gosched()
			}
		}
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("canceled active derivation = %v", err)
			}
		case <-watchdog.C:
			var stacks strings.Builder
			_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
			t.Fatalf("canceled derivation did not finish\n%s", stacks.String())
		}
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				for range 20 {
					valid, err := auth.IsValidPassword(t.Context(), "test")
					if err != nil || !valid {
						t.Errorf("concurrent verification=%v,%v", valid, err)
					}
				}
			})
		}
		wg.Go(func() {
			for range 20 {
				err := manager.Do(t.Context(), func(ctx context.Context) error {
					return opts.Update(ctx, map[string]any{"web_password": testHash})
				})
				if err != nil {
					t.Errorf("concurrent reconfiguration: %v", err)
				}
			}
		})
		wg.Wait()
		verifierBudget.Lock()
		active, memory := verifierBudget.active, verifierBudget.memory
		verifierBudget.Unlock()
		if diff := gocmp.Diff([]uint32{0, 0}, []uint32{uint32(active), memory}); diff != "" {
			t.Fatal(diff)
		}
		status, _, _ = request(t, server.Client(), "GET", server.URL+"/api?token=test", "", nil)
		if status != 200 {
			t.Fatalf("post-release status=%d", status)
		}
	})
}
