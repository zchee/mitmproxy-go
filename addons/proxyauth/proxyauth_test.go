// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"weak"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// Upstream test_mkauth and test_parse_http_basic_auth*.
func TestBasicAuth(t *testing.T) {
	tests := map[string]struct {
		input string
		want  []string
	}{
		"long s scheme":       {input: "baſic dGVzdDp0ZXN0"},
		"control whitespace":  {"basic\x1cdGVzdDp0ZXN0\x1f", []string{"basic", "test", "test"}},
		"empty":               {input: ""},
		"unknown scheme":      {input: "foo bar"},
		"invalid base64":      {input: "basic abc"},
		"missing colon":       {input: "basic Zm9v"},
		"extra fields":        {input: "basic Zm9vOmJhcg== extra"},
		"oversized":           {input: "basic " + strings.Repeat("A", 65537)},
		"basic":               {"basic dGVzdDp0ZXN0\n", []string{"basic", "test", "test"}},
		"password colon":      {"basic dGVzdDpwYXNzOndvcmQ=\n", []string{"basic", "test", "pass:word"}},
		"case and whitespace": {" \tBaSiC\n dGVzdDp0ZXN0 \r", []string{"BaSiC", "test", "test"}},
		"empty credentials":   {"basic Og==", []string{"basic", "", ""}},
		"replacement utf8":    {"basic /zo=", []string{"basic", "�", ""}},
		"ignored nonalphabet": {"basic dG!VzdDp0ZXN0", []string{"basic", "test", "test"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			scheme, user, password, err := ParseHTTPBasicAuth(tt.input)
			if tt.want == nil {
				if err == nil {
					t.Fatal("malformed header accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, []string{scheme, user, password}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for _, scheme := range []string{"", "basic", "foobar"} {
		want := scheme + " dXNlcm5hbWU6cGFzc3dvcmQ=\n"
		if diff := gocmp.Diff(want, MakeAuth("username", "password", scheme)); diff != "" {
			t.Fatal(diff)
		}
	}
}

func newAuth(t *testing.T, spec *string) (*ProxyAuth, *addon.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	p := New(opts)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if err := setAuth(t, m, opts, spec); err != nil {
		t.Fatal(err)
	}
	return p, m, opts
}

func setAuth(t *testing.T, m *addon.Manager, opts *options.Manager, spec *string) error {
	t.Helper()
	return m.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"proxyauth": spec}) })
}

// Upstream test_is_http_proxy, test_http_auth_header,
// test_make_auth_required_response and TestProxyAuth.test_authenticate.
func TestAuthenticate(t *testing.T) {
	tests := map[string]struct {
		mode      string
		header    string
		challenge string
		status    int
		reason    string
	}{
		"regular":  {"regular", "Proxy-Authorization", "Proxy-Authenticate", 407, "Proxy Authentication Required"},
		"upstream": {"upstream:proxy", "Proxy-Authorization", "Proxy-Authenticate", 407, "Proxy Authentication Required"},
		"reverse":  {"reverse:https://example.com", "Authorization", "WWW-Authenticate", 401, "Unauthorized"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, m, _ := newAuth(t, new("test:test"))
			for _, valid := range []bool{false, true} {
				f := testflow.TFlow()
				f.ClientConn.ProxyMode = tt.mode
				f.Request.Headers.Set("X-Unrelated", "keep")
				if valid {
					f.Request.Headers.Set(tt.header, MakeAuth("test", "test", "basic"))
				}
				if err := m.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
					t.Fatal(err)
				}
				if valid {
					if f.Response != nil || f.Request.Headers.Has(tt.header) {
						t.Fatal("successful authentication failed to strip its header", f.Response)
					}
					got, _ := f.Metadata.Get("proxyauth")
					if diff := gocmp.Diff([]any{"test", "test"}, got); diff != "" {
						t.Fatal(diff)
					}
				} else {
					if f.Response == nil || f.Response.StatusCode != tt.status {
						t.Fatalf("response = %#v", f.Response)
					}
					if got := f.Response.Headers.Get(tt.challenge); got != `Basic realm="mitmproxy"` {
						t.Fatalf("challenge = %q", got)
					}
					wantBody := fmt.Sprintf("<html><head><title>%d %s</title></head><body><h1>%d %s</h1></body></html>", tt.status, tt.reason, tt.status, tt.reason)
					if diff := gocmp.Diff(wantBody, string(f.Response.RawContent)); diff != "" {
						t.Fatal(diff)
					}
				}
				if got := f.Request.Headers.Get("X-Unrelated"); got != "keep" {
					t.Fatal("unrelated header changed")
				}
			}
		})
	}
}

// Upstream TestProxyAuth.test_handlers. TestProxyAuth.test_socks5 is not
// applicable until the SOCKS5 proxy mode is implemented.
func TestHandlers(t *testing.T) {
	p, m, opts := newAuth(t, new("any"))
	connect := testflow.TFlow()
	connect.Request.Method = "CONNECT"
	if err := m.Hook(t.Context(), addon.HTTPConnectHook{Flow: connect}); err != nil {
		t.Fatal(err)
	}
	if connect.Response == nil || connect.Response.StatusCode != 407 {
		t.Fatal("unauthenticated CONNECT accepted")
	}
	connect.Response = nil
	connect.Request.Headers.Set("Proxy-Authorization", MakeAuth("test", "test", "basic"))
	if err := m.Hook(t.Context(), addon.HTTPConnectHook{Flow: connect}); err != nil {
		t.Fatal(err)
	}
	if connect.Response != nil {
		t.Fatal("authenticated CONNECT rejected")
	}
	f := testflow.TFlow()
	f.ClientConn = connect.ClientConn
	if err := m.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	got, _ := f.Metadata.Get("proxyauth")
	if f.Response != nil {
		t.Fatal("CONNECT authentication not persistent")
	}
	if diff := gocmp.Diff([]any{"test", "test"}, got); diff != "" {
		t.Fatal(diff)
	}
	got.([]any)[0] = "changed"
	f2 := testflow.TFlow()
	f2.ClientConn = connect.ClientConn
	if err := m.Hook(t.Context(), addon.RequestHeadersHook{Flow: f2}); err != nil {
		t.Fatal(err)
	}
	got, _ = f2.Metadata.Get("proxyauth")
	if diff := gocmp.Diff([]any{"test", "test"}, got); diff != "" {
		t.Fatal("metadata aliased cached credentials:", diff)
	}
	other := requestWithAuth("other", "password")
	if err := m.Hook(t.Context(), addon.HTTPConnectHook{Flow: other}); err != nil {
		t.Fatal(err)
	}
	// The cleanup callback deletes only its own key, independent of GC timing.
	p.authenticated.Delete(weak.Make(connect.ClientConn))
	if _, ok := p.authenticated.Load(weak.Make(connect.ClientConn)); ok {
		t.Fatal("cleanup retained its client")
	}
	if _, ok := p.authenticated.Load(weak.Make(other.ClientConn)); !ok {
		t.Fatal("cleanup deleted another live client")
	}
	runtime.KeepAlive(connect.ClientConn)
	runtime.KeepAlive(other.ClientConn)
	f = testflow.TFlow()
	f.IsReplay = new("request")
	if err := m.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if f.Response != nil {
		t.Fatal("replayed request challenged")
	}
	if err := setAuth(t, m, opts, nil); err != nil {
		t.Fatal(err)
	}
	f = testflow.TFlow()
	if err := m.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if f.Response != nil {
		t.Fatal("disabled authentication challenged")
	}
}

// Upstream TestProxyAuth.test_configure, plus option rollback.
func TestConfigure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "htpasswd")
	if err := os.WriteFile(file, []byte("test:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ spec, wantError string }{
		"any": {"any", ""}, "single": {"test:test", ""}, "empty": {"", ""},
		"htpasswd":            {"@" + file, ""},
		"missing file":        {"@" + file + "missing", "Could not open htpasswd file"},
		"invalid":             {"foo", "Invalid proxyauth specification."},
		"multiple colons":     {"foo:bar:baz", "Invalid single-user auth specification."},
		"ldap":                {"ldap:localhost:cn=default,dc=cdhdt,dc=com:password:ou=application,dc=cdhdt,dc=com", ""},
		"ldap port":           {"ldap:localhost:1234:cn=default:password:dc=cdhdt,dc=com", ""},
		"ldap search key":     {"ldap:localhost:1234:cn=default:password:dc=cdhdt,dc=com?search_filter_key=SamAccountName", ""},
		"ldap missing fields": {"ldap:test:test:test", "Invalid LDAP specification"},
		"ldap wrong key":      {"ldap:localhost:1234:cn=default:password:dc=example?key=1", "Invalid LDAP specification"},
		"ldap malformed":      {"ldap:fake_serveruid=?dc=example,dc=com:person", "Invalid LDAP specification"},
		"ldap wrong scheme":   {"ldapssssssss:fake_server:dn:password:tree", "Invalid LDAP specification"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, m, opts := newAuth(t, new("test:test"))
			err := setAuth(t, m, opts, &tt.spec)
			if tt.wantError != "" {
				var optionError *options.OptionsError
				if !errors.As(err, &optionError) || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want %q", err, tt.wantError)
				}
				if got := opts.OptStr("proxyauth"); got == nil || *got != "test:test" {
					t.Fatal("rejected option not rolled back")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(tt.spec, "ldap") && tt.wantError == "" {
				return
			}
			f := testflow.TFlow()
			f.Request.Headers.Set("Proxy-Authorization", MakeAuth("test", "test", "basic"))
			if err := m.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if f.Response != nil {
				t.Fatal("valid credentials rejected after configure", f.Response)
			}
		})
	}
	if err := os.WriteFile(file, []byte("malformed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, m, opts := newAuth(t, nil)
	if err := setAuth(t, m, opts, new("@"+file)); err == nil {
		t.Fatal("malformed htpasswd accepted")
	}
}

func TestPasswords(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	if err := os.WriteFile(filepath.Join(home, "htpasswd"), []byte("test:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		spec, username, password string
		accepted                 bool
	}{
		"single correct":                    {"test:test", "test", "test", true},
		"single wrong password":             {"test:test", "test", "wrong", false},
		"single same-length wrong password": {"test:test", "test", "tesx", false},
		"single shorter wrong password":     {"test:test", "test", "tes", false},
		"single empty wrong password":       {"test:test", "test", "", false},
		"single wrong user":                 {"test:test", "wrong", "test", false},
		"single same-length wrong user":     {"test:test", "tesx", "test", false},
		"single shorter wrong user":         {"test:test", "tes", "test", false},
		"single empty credentials":          {":", "", "", true},
		"htpasswd home":                     {"@~/htpasswd", "test", "test", true},
		"htpasswd wrong password":           {"@~/htpasswd", "test", "wrong", false},
		"htpasswd wrong user":               {"@~/htpasswd", "wrong", "test", false},
		"any empty":                         {"any", "", "", true},
		"any arbitrary":                     {"any", "user", "p:a:s:s", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, manager, _ := newAuth(t, &tt.spec)
			f := requestWithAuth(tt.username, tt.password)
			if err := manager.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if (f.Response == nil) != tt.accepted {
				t.Fatalf("accepted = %v, want %v", f.Response == nil, tt.accepted)
			}
			_, metadata := f.Metadata.Get("proxyauth")
			if metadata != tt.accepted || f.Request.Headers.Has("Proxy-Authorization") == tt.accepted {
				t.Fatal("authentication metadata or header removal disagrees with verdict")
			}
		})
	}
}

func TestOptions(t *testing.T) {
	_, _, opts := newAuth(t, nil)
	opt, ok := opts.Lookup("proxyauth")
	if !ok {
		t.Fatal("missing proxyauth")
	}
	wantHelp := `Require proxy authentication. Format: "username:pass", "any" to accept any user/pass combination, "@path" to use an Apache htpasswd file, or "ldap[s]:url_server_ldap[:port]:dn_auth:password:dn_subtree[?search_filter_key=...]" for LDAP authentication.`
	if opt.Type() != options.TypeOptStr || opt.Default().(*string) != nil || opt.Help() != wantHelp {
		t.Fatalf("option mismatch: %v, %v, %q", opt.Type(), opt.Default(), opt.Help())
	}
}

func TestConcurrentRequests(t *testing.T) {
	_, m, _ := newAuth(t, new("test:test"))
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			f := testflow.TFlow()
			f.Request.Headers.Set("Proxy-Authorization", MakeAuth("test", "test", "basic"))
			if err := m.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
				t.Error(err)
			}
			if f.Response != nil {
				t.Error("valid concurrent request rejected")
			}
		})
	}
	wg.Wait()
}

func requestWithAuth(user, password string) *flow.HTTPFlow {
	f := testflow.TFlow()
	f.Request.Headers.Set("Proxy-Authorization", MakeAuth(user, password, "basic"))
	return f
}
