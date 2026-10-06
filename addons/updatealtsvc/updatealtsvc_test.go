// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updatealtsvc

import (
	"context"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// TestSimple ports test_simple.
func TestSimple(t *testing.T) {
	tests := map[string]struct {
		header string
		port   int
		want   string
	}{
		"success: simple":              {`h3="example.com:443"; ma=3600, h2=":443"; ma=3600`, 1234, `h3=":1234"; ma=3600, h2=":1234"; ma=3600`},
		"success: Unicode digits":      {`h3="example.com:٤٤٣"`, 1234, `h3=":1234"`},
		"success: empty":               {"", 1234, ""},
		"skip: no port":                {"clear", 1234, "clear"},
		"success: prefix of long port": {`h3="a:123456"`, 1234, `h3=":12346"`},
		"success: zero listen port":    {`h3=":443"`, 0, `h3=":0"`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := updateHeader(test.header, test.port)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func setup(t *testing.T) (*addon.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	if err := mgr.Add(t.Context(), New(opts)); err != nil {
		t.Fatal(err)
	}
	return mgr, opts
}

// TestUpdatesAltSvcHeader ports test_updates_alt_svc_header.
func TestUpdatesAltSvcHeader(t *testing.T) {
	tests := map[string]struct {
		mode string
		keep bool
		want string
	}{
		"skip: regular":    {"regular", false, `h3="example.com:443"; ma=3600, h2=":443"; ma=3600`},
		"skip: keep":       {"reverse:https://example.com", true, `h3="example.com:443"; ma=3600, h2=":443"; ma=3600`},
		"success: reverse": {"reverse:https://example.com", false, `h3=":1234"; ma=3600, h2=":1234"; ma=3600`},
		"success: listen override still uses socket": {"reverse:https://example.com@8443", false, `h3=":1234"; ma=3600, h2=":1234"; ma=3600`},
		"skip: invalid stored mode":                  {"not-a-mode", false, `h3="example.com:443"; ma=3600, h2=":443"; ma=3600`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, opts := setup(t)
			if err := mgr.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"keep_alt_svc_header": test.keep})
			}); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow()
			f.Response = testflow.TResp()
			f.ClientConn.ProxyMode = test.mode
			f.ClientConn.Sockname = &connection.Address{Host: "", Port: 1234}
			f.Response.Headers.Set("Alt-Svc", `h3="example.com:443"; ma=3600, h2=":443"; ma=3600`)
			f.Response.Headers.Set("Content-Type", "application/xml")
			if err := mgr.Hook(t.Context(), addon.ResponseHeadersHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, f.Response.Headers.Get("alt-svc")); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff("application/xml", f.Response.Headers.Get("content-type")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestDuplicateHeaders(t *testing.T) {
	mgr, _ := setup(t)
	f := testflow.TFlow()
	f.Response = testflow.TResp()
	f.ClientConn.ProxyMode = "reverse:https://example.com"
	f.ClientConn.Sockname.Port = 1234
	f.Response.Headers.SetAll("Alt-Svc", []string{`h3="a:443"`, `h2="b:443"`})
	if err := mgr.Hook(t.Context(), addon.ResponseHeadersHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{`h3=":1234", h2=":1234"`}, f.Response.Headers.GetAll("alt-svc")); diff != "" {
		t.Fatal(diff)
	}
	f.Response.Headers.Del("alt-svc")
	if err := mgr.Hook(t.Context(), addon.ResponseHeadersHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if f.Response.Headers.Has("alt-svc") {
		t.Fatal("absent header created")
	}
}

func TestInvalidFlowAndHeader(t *testing.T) {
	tests := map[string]struct {
		response, client, socket bool
		header                   string
		wantError                bool
	}{
		"error: missing response":   {false, true, true, "", true},
		"error: missing client":     {true, false, true, `h3=":443"`, true},
		"error: missing socket":     {true, true, false, `h3=":443"`, true},
		"error: malformed UTF8":     {true, true, true, string([]byte{0xff}) + `:443`, true},
		"skip: no header no socket": {true, true, false, "", false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, opts := setup(t)
			f := testflow.TFlow()
			if test.response {
				f.Response = testflow.TResp()
				f.Response.Headers.Del("alt-svc")
				if test.header != "" {
					f.Response.Headers.Set("alt-svc", test.header)
				}
			}
			f.ClientConn.ProxyMode = "reverse:https://example.com"
			if !test.client {
				f.ClientConn = nil
			} else if !test.socket {
				f.ClientConn.Sockname = nil
			}
			err := mgr.Do(t.Context(), func(ctx context.Context) error { return New(opts).ResponseHeaders(ctx, f) })
			if (err != nil) != test.wantError {
				t.Fatal(err)
			}
			if f.Response != nil && test.header != "" {
				if diff := gocmp.Diff(test.header, f.Response.Headers.Get("alt-svc")); diff != "" {
					t.Fatal("partial rewrite", diff)
				}
			}
		})
	}
}

func TestConcurrentDispatch(t *testing.T) {
	mgr, _ := setup(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			f := testflow.TFlow()
			f.Response = testflow.TResp()
			f.ClientConn.ProxyMode = "reverse:https://example.com"
			f.Response.Headers.Set("alt-svc", `h3=":443"`)
			if err := mgr.Hook(t.Context(), addon.ResponseHeadersHook{Flow: f}); err != nil {
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
	}{"keep_alt_svc_header": {options.TypeBool, false, "Reverse Proxy: Keep Alt-Svc headers as-is, even if they do not point to mitmproxy. Enabling this option may cause clients to bypass the proxy."}}
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
	if s.Name() != "updatealtsvc" {
		t.Fatal(s.Name())
	}
}
