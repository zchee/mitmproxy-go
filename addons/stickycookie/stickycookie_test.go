// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package stickycookie

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// TestDomainMatch ports test_domain_match and pins Python cookiejar's surprising edges.
func TestDomainMatch(t *testing.T) {
	tests := map[string]struct {
		host, domain string
		want         bool
	}{
		"success: subdomain": {"www.google.com", ".google.com", true}, "success: apex": {"google.com", ".google.com", true}, "success: case": {"WWW.Google.COM", ".GOOGLE.COM", true}, "skip: bare parent": {"www.google.com", "google.com", false}, "success: trimmed dots": {"google.com", "...google.com...", true}, "skip: digit hostname": {"foo.123", ".123", false}, "success: identical IP": {"127.0.0.1", "127.0.0.1", true}, "skip: IP suffix": {"127.0.0.1", ".0.0.1", false}, "success: interior substring": {"www.google.com.example", ".google.com", true}, "skip: unrelated": {"google.com", ".evil.com", false}, "skip: empty": {"", ".com", false}, "success: Unicode lowercase expansion": {"İ.example", "i̇.example", true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(test.want, domainMatch(test.host, test.domain)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func setup(t *testing.T, pattern *string) (*addon.Manager, *options.Manager, *StickyCookie) {
	t.Helper()
	opts := options.New()
	mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	s := New(opts)
	if err := mgr.Add(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"stickycookie": pattern}) }); err != nil {
		t.Fatal(err)
	}
	return mgr, opts, s
}

// TestConfig ports test_config.
func TestConfig(t *testing.T) {
	mgr, opts, s := setup(t, nil)
	err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"stickycookie": new("~b")}) })
	if err == nil || !strings.Contains(err.Error(), "invalid filter expression") {
		t.Fatal(err)
	}
	for _, pattern := range []*string{new("foo"), nil, new("")} {
		if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"stickycookie": pattern}) }); err != nil {
			t.Fatal(err)
		}
		want := pattern != nil && *pattern != ""
		if (s.flt != nil) != want {
			t.Fatal("incorrect filter enablement")
		}
	}
}

// TestResponse ports test_simple, test_response, test_response_multiple,
// test_response_weird, test_response_overwrite, test_response_delete and test_request.
func TestResponse(t *testing.T) {
	tests := map[string]struct {
		host    string
		cookies []string
		want    []string
	}{
		"success: simple":                {"www.google.com", []string{"foo=bar"}, []string{"foo=bar"}},
		"skip: response domain mismatch": {"host", []string{"SSID=mooo; domain=.google.com, FOO=bar; Domain=.google.com; Path=/; Expires=Wed, 13-Jan-2021 22:23:01 GMT; Secure;"}, nil},
		"success: response":              {"www.google.com", []string{"SSID=mooo; domain=.google.com, FOO=bar; Domain=.google.com; Path=/; Expires=Wed, 13-Jan-2021 22:23:01 GMT; Secure;"}, []string{"SSID=mooo"}},
		"success: multiple":              {"www.google.com", []string{"somecookie=test; Path=/", "othercookie=helloworld; Path=/"}, []string{"somecookie=test", "othercookie=helloworld"}},
		"success: weird":                 {"www.google.com", []string{"foo/bar=hello", "foo:bar=world", "foo@bar=fizz"}, []string{"foo/bar=hello", "foo:bar=world", "foo@bar=fizz"}},
		"success: overwrite":             {"www.google.com", []string{"somecookie=helloworld; Path=/", "somecookie=newvalue; Path=/"}, []string{"somecookie=newvalue"}},
		"success: delete":                {"www.google.com", []string{"duffer=zafar; Path=/", "duffer=; Expires=Thu, 01-Jan-1970 00:00:00 GMT"}, nil},
		"success: bare cookie":           {"www.google.com", []string{"flag"}, []string{"flag"}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, s := setup(t, new(".*"))
			f := testflow.TFlow()
			f.Request.Host = test.host
			f.Request.Port = 80
			f.Request.Path = "/"
			f.Response = testflow.TResp()
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			for _, cookie := range test.cookies {
				f.Response.Headers.Set("Set-Cookie", cookie)
				if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
					t.Fatal(err)
				}
			}
			if f.Request.Headers.Has("cookie") {
				t.Fatal("response prematurely modifies request")
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			want := strings.Join(test.want, "; ")
			if diff := gocmp.Diff(want, f.Request.Headers.Get("cookie")); diff != "" {
				t.Fatal(diff)
			}
			marked, _ := f.Metadata.Get("stickycookie")
			if (marked == true) != (len(test.want) > 0) {
				t.Fatal("incorrect sticky metadata")
			}
			if len(test.want) == 0 && s.jar.Len() != 0 {
				t.Fatal("empty origin was not removed")
			}
		})
	}
}

func TestRequestScope(t *testing.T) {
	tests := map[string]struct {
		host   string
		port   int
		path   string
		filter string
		want   bool
	}{"success: path prefix": {"www.google.com", 80, "/some/child", ".*", true}, "skip: host": {"example.com", 80, "/some/child", ".*", false}, "skip: port": {"www.google.com", 81, "/some/child", ".*", false}, "skip: path": {"www.google.com", 80, "/other", ".*", false}, "skip: filter": {"www.google.com", 80, "/some/child", "~u unmatched", false}, "success: secure ignored": {"www.google.com", 80, "/something", ".*", true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, new(test.filter))
			response := testflow.TFlow()
			response.Request.Host = "www.google.com"
			response.Request.Port = 80
			response.Response = testflow.TResp()
			response.Response.Headers.Set("Set-Cookie", "one=value; Path=/some; Secure")
			if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: response}); err != nil {
				t.Fatal(err)
			}
			request := testflow.TFlow()
			request.Request.Host = test.host
			request.Request.Port = test.port
			request.Request.Path = test.path
			request.Request.Scheme = "http"
			request.Request.Headers.Set("Cookie", "existing=keep")
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: request}); err != nil {
				t.Fatal(err)
			}
			want := "existing=keep"
			if test.want {
				want = "one=value"
			}
			if diff := gocmp.Diff(want, request.Request.Headers.Get("Cookie")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestBoundAndRecovery(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	mgr, _, s := setup(t, new(".*"))
	f := testflow.TFlow()
	f.Response = testflow.TResp()
	f.Response.Headers.Set("Set-Cookie", "small=keep")
	if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	retained := s.bytes
	f.Response.Headers.Set("Set-Cookie", "oversized="+strings.Repeat("x", maxJarBytes))
	if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
		t.Fatal("overflow must not fail live flow", err)
	}
	if s.count != 1 || s.bytes != retained || !s.overflow {
		t.Fatal("overflow retained cookie or failed to mark episode")
	}
	f.Response.Headers.Set("Set-Cookie", "later=drop")
	if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if s.count != 1 {
		t.Fatal("growing write retained during overflow")
	}
	warning := fmt.Sprintf("stickycookie: jar limit reached (1 cookies, %d); new cookies are not retained until existing ones expire or are deleted", retained)
	if strings.Count(logs.String(), "jar limit reached") != 1 || !strings.Contains(logs.String(), warning) {
		t.Fatal("warning episode text/count incorrect", logs.String())
	}
	f.Response.Headers.Set("Set-Cookie", "small=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
	if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if s.count != 0 || s.bytes != 0 || s.overflow || s.jar.Len() != 0 {
		t.Fatal("deletion did not recover capacity")
	}
}

func TestCountBound(t *testing.T) {
	mgr, _, s := setup(t, new(".*"))
	f := testflow.TFlow()
	f.Response = testflow.TResp()
	for i := range maxJarCookies {
		f.Response.Headers.Set("Set-Cookie", fmt.Sprintf("cookie%d=", i))
		if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
			t.Fatal(err)
		}
	}
	if s.count != maxJarCookies {
		t.Fatal("jar did not fill to exact count bound")
	}
	f.Response.Headers.Set("Set-Cookie", "extra=drop")
	if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if s.count != maxJarCookies || !s.overflow {
		t.Fatal("count bound not enforced")
	}
	f.Response.Headers.Set("Set-Cookie", "cookie0=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
	if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	f.Response.Headers.Set("Set-Cookie", "extra=keep")
	if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if s.count != maxJarCookies || s.overflow {
		t.Fatal("deletion did not restore admission")
	}
}

func TestOriginOrdering(t *testing.T) {
	mgr, opts, _ := setup(t, new(".*"))
	f := testflow.TFlow()
	f.Request.Host = "www.google.com"
	f.Request.Port = 80
	f.Request.Path = "/a"
	f.Response = testflow.TResp()
	for _, cookie := range []string{"one=first; Domain=.google.com", "two=second; Path=/a", "one=last; Domain=.google.com"} {
		f.Response.Headers.Set("Set-Cookie", cookie)
		if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
			t.Fatal(err)
		}
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error {
		return opts.Update(ctx, map[string]any{"stickycookie": (*string)(nil)})
	}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"stickycookie": new(".*")}) }); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff("one=last; two=second", f.Request.Headers.Get("Cookie")); diff != "" {
		t.Fatal(diff)
	}
}

func TestConcurrentDispatch(t *testing.T) {
	mgr, _, _ := setup(t, new(".*"))
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			f := testflow.TFlow()
			f.Response = testflow.TResp()
			f.Response.Headers.Set("Set-Cookie", "name=value")
			if err := mgr.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
				t.Error(err)
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestOptionsAndCommands(t *testing.T) {
	opts := options.New()
	cmds := command.NewManager()
	mgr := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(mgr.Close)
	s := New(opts)
	if err := mgr.Add(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{"stickycookie": {options.TypeOptStr, (*string)(nil), "Set sticky cookie filter. Matched against requests."}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o, ok := opts.Lookup(name)
			if !ok {
				t.Fatal("missing option")
			}
			if diff := gocmp.Diff([]any{test.typ, test.def, test.help}, []any{o.Type(), o.Default(), o.Help()}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for name := range cmds.Commands() {
		t.Errorf("unexpected command %s; upstream declares none", name)
	}
	if s.Name() != "stickycookie" {
		t.Fatal(s.Name())
	}
}
