// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package upstreamauth

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T) (*UpstreamAuth, *addon.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	auth := New(opts)
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), auth); err != nil {
		t.Fatal(err)
	}
	return auth, manager, opts
}

func configure(t *testing.T, manager *addon.Manager, opts *options.Manager, spec *string) error {
	t.Helper()
	return manager.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"upstream_auth": spec}) })
}

// Upstream test_configure, including rollback and the unanchored validation.
func TestConfigure(t *testing.T) {
	tests := map[string]struct {
		spec  *string
		valid bool
	}{
		"basic": {new("test:test"), true}, "empty password": {new("test:"), true}, "disabled": {nil, true},
		"empty": {new(""), false}, "colon": {new(":"), false}, "missing user": {new(":test"), false},
		"password colons": {new("test:p:a:ss"), true}, "colon user": {new("::"), true},
		"newline before colon": {new("\n:private-password"), false}, "search after newline": {new("\nuser:pass"), true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auth, manager, opts := setup(t)
			if err := configure(t, manager, opts, new("before:before")); err != nil {
				t.Fatal(err)
			}
			err := configure(t, manager, opts, tt.spec)
			if (err == nil) != tt.valid {
				t.Fatalf("valid = %v, want %v: %v", err == nil, tt.valid, err)
			}
			want := ""
			if !tt.valid {
				if strings.Contains(err.Error(), "private-password") {
					t.Fatal("error disclosed password")
				}
				if got := opts.OptStr("upstream_auth"); got == nil || *got != "before:before" {
					t.Fatal("option not rolled back")
				}
				want = "Basic " + base64.StdEncoding.EncodeToString([]byte("before:before"))
			} else if tt.spec != nil {
				want = "Basic " + base64.StdEncoding.EncodeToString([]byte(*tt.spec))
			}
			if diff := gocmp.Diff(want, auth.auth); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// Upstream test_simple, including tunneled HTTPS and preservation of headers.
func TestHooks(t *testing.T) {
	tests := map[string]struct {
		mode, scheme, header string
		connect, disabled    bool
	}{
		"connect":          {mode: "regular", scheme: "https", header: "Proxy-Authorization", connect: true},
		"regular":          {mode: "regular", scheme: "http"},
		"upstream http":    {mode: "upstream:127.0.0.1", scheme: "http", header: "Proxy-Authorization"},
		"upstream https":   {mode: "upstream:127.0.0.1", scheme: "https"},
		"reverse":          {mode: "reverse:127.0.0.1", scheme: "https", header: "Authorization"},
		"disabled connect": {mode: "regular", connect: true, disabled: true},
		"disabled reverse": {mode: "reverse:127.0.0.1", scheme: "http", disabled: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, manager, opts := setup(t)
			if !tt.disabled {
				if err := configure(t, manager, opts, new("foo:bar")); err != nil {
					t.Fatal(err)
				}
			}
			f := testflow.TFlow()
			f.ClientConn.ProxyMode, f.Request.Scheme = tt.mode, tt.scheme
			f.Request.Headers.Set("X-Unrelated", "preserve")
			f.Request.Headers.Set("Authorization", "preserve")
			f.Request.Headers.Set("Proxy-Authorization", "preserve")
			var err error
			if tt.connect {
				err = manager.Hook(t.Context(), addon.HTTPConnectUpstreamHook{Flow: f})
			} else {
				err = manager.Hook(t.Context(), addon.RequestHeadersHook{Flow: f})
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, header := range []string{"Authorization", "Proxy-Authorization"} {
				want := "preserve"
				if header == tt.header {
					want = "Basic Zm9vOmJhcg=="
				}
				if diff := gocmp.Diff(want, f.Request.Headers.Get(header)); diff != "" {
					t.Fatal(header, diff)
				}
			}
			if f.Request.Headers.Get("X-Unrelated") != "preserve" {
				t.Fatal("unrelated header changed")
			}
		})
	}
}

func TestOptions(t *testing.T) {
	_, _, opts := setup(t)
	opt, ok := opts.Lookup("upstream_auth")
	if !ok {
		t.Fatal("missing upstream_auth option")
	}
	if opt.Type() != options.TypeOptStr || opt.Default().(*string) != nil || opt.Help() != "Add HTTP Basic authentication to upstream proxy and reverse proxy requests. Format: username:password." {
		t.Fatal("option definition differs from upstream")
	}
}
