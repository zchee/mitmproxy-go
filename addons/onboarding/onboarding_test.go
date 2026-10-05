// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package onboarding

import (
	"context"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T) (*addon.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), New(opts)); err != nil {
		t.Fatal(err)
	}
	return manager, opts
}

func update(t *testing.T, manager *addon.Manager, opts *options.Manager, values map[string]any) {
	t.Helper()
	if err := manager.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, values) }); err != nil {
		t.Fatal(err)
	}
}

func request(t *testing.T, manager *addon.Manager, method, url string) *flow.HTTPFlow {
	t.Helper()
	f := testflow.TFlow()
	var err error
	f.Request, err = httpmsg.MakeRequest(method, url, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestServed ports TestApp.test_basic, test_cert and test_head from upstream
// test/mitmproxy/addons/test_onboarding.py through the real addon dispatcher.
func TestServed(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		method, path string
		attachment   bool
	}{
		"index":       {"GET", "/", false},
		"pem":         {"GET", "/cert/pem", true},
		"p12":         {"GET", "/cert/p12", true},
		"cer":         {"GET", "/cert/cer", true},
		"magisk":      {"GET", "/cert/magisk", true},
		"head pem":    {"HEAD", "/cert/pem", true},
		"head p12":    {"HEAD", "/cert/p12", true},
		"head cer":    {"HEAD", "/cert/cer", true},
		"head magisk": {"HEAD", "/cert/magisk", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manager, opts := setup(t)
			update(t, manager, opts, map[string]any{"confdir": testutil.FixturePath(t, "mitmproxy/confdir")})
			f := request(t, manager, tt.method, "http://"+opts.Str("onboarding_host")+tt.path)
			if f.Response == nil {
				t.Fatal("request hook did not set a response")
			}
			if diff := gocmp.Diff(200, f.Response.StatusCode); diff != "" {
				t.Fatal(diff)
			}
			for _, header := range []string{"Content-Length", "Content-Type"} {
				if f.Response.Headers.Get(header) == "" {
					t.Errorf("missing %s", header)
				}
			}
			if tt.attachment && !strings.Contains(f.Response.Headers.Get("Content-Disposition"), "attachment") {
				t.Errorf("Content-Disposition %q is not an attachment", f.Response.Headers.Get("Content-Disposition"))
			}
			if tt.method == "HEAD" {
				if len(f.Response.RawContent) != 0 {
					t.Error("HEAD response has a body")
				}
			} else if len(f.Response.RawContent) == 0 {
				t.Error("empty response body")
			}
		})
	}
}

func TestNotServed(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		values map[string]any
		url    string
	}{
		"other host":       {nil, "http://example.com/"},
		"disabled":         {map[string]any{"onboarding": false}, "http://mitm.it/"},
		"reconfigured off": {map[string]any{"onboarding_host": "onboarding.local"}, "http://mitm.it/"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manager, opts := setup(t)
			if tt.values != nil {
				update(t, manager, opts, tt.values)
			}
			if f := request(t, manager, "GET", tt.url); f.Response != nil {
				t.Fatalf("unexpected response %d", f.Response.StatusCode)
			}
		})
	}
}

func TestReconfiguredHost(t *testing.T) {
	t.Parallel()
	manager, opts := setup(t)
	update(t, manager, opts, map[string]any{"onboarding_host": "onboarding.local"})
	f := request(t, manager, "GET", "http://onboarding.local:8888/")
	if f.Response == nil || f.Response.StatusCode != 200 {
		t.Fatalf("reconfigured host not served: %+v", f.Response)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		kind options.Type
		def  any
		help string
	}{
		"onboarding":      {options.TypeBool, true, "Toggle the mitmproxy onboarding app."},
		"onboarding_host": {options.TypeStr, "mitm.it", "Onboarding app domain. For transparent mode, use an IP when a DNS entry for the app domain is not present."},
	}
	_, opts := setup(t)
	if opts.Has("onboarding_port") {
		t.Fatal("onboarding_port is not an upstream option")
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := opts.Lookup(name)
			if !ok {
				t.Fatalf("missing %s option", name)
			}
			if opt.Type() != tt.kind || opt.Default() != tt.def || opt.Help() != tt.help {
				t.Fatalf("option %s = (%v, %v, %q), want (%v, %v, %q)", name, opt.Type(), opt.Default(), opt.Help(), tt.kind, tt.def, tt.help)
			}
		})
	}
}
