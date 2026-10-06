// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package stickyauth

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

func setup(t *testing.T, pattern *string) (*addon.Manager, *options.Manager, *StickyAuth) {
	t.Helper()
	opts := options.New()
	mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	s := New(opts)
	if err := mgr.Add(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"stickyauth": pattern}) }); err != nil {
		t.Fatal(err)
	}
	return mgr, opts, s
}

// TestConfigure ports test_configure.
func TestConfigure(t *testing.T) {
	mgr, opts, s := setup(t, new("~s"))
	if s.flt == nil {
		t.Fatal("filter not installed")
	}
	err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"stickyauth": new("~~")}) })
	if err == nil || !strings.Contains(err.Error(), "invalid filter expression") {
		t.Fatal(err)
	}
	for _, pattern := range []*string{nil, new("")} {
		if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"stickyauth": pattern}) }); err != nil {
			t.Fatal(err)
		}
		if s.flt != nil {
			t.Fatal("filter remains enabled")
		}
	}
}

// TestSimple ports test_simple and covers host-only scoping and capture before filtering.
func TestSimple(t *testing.T) {
	tests := map[string]struct {
		filter, host, scheme string
		port                 int
		auth                 []string
		want                 string
	}{
		"success: simple":                    {".*", "address", "http", 22, []string{"foo"}, "foo"},
		"success: different port and scheme": {".*", "address", "https", 443, []string{"foo"}, "foo"},
		"skip: exact host case":              {".*", "ADDRESS", "http", 22, []string{"foo"}, ""},
		"skip: different host":               {".*", "elsewhere", "http", 22, []string{"foo"}, ""},
		"skip: disabled":                     {"", "address", "http", 22, []string{"foo"}, ""},
		"skip: request filter":               {"~u nomatch", "address", "http", 22, []string{"foo"}, ""},
		"success: capture unmatched":         {"~u /matched", "address", "http", 22, []string{"foo"}, "foo"},
		"success: duplicate folded":          {".*", "address", "http", 22, []string{"foo", "bar"}, "foo, bar"},
		"success: empty header":              {".*", "address", "http", 22, []string{""}, ""},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, s := setup(t, new(test.filter))
			f := testflow.TFlow()
			f.Request.Host = "address"
			f.Request.Path = "/unmatched"
			f.Request.Headers.SetAll("Authorization", test.auth)
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if test.filter != "" {
				if _, ok := s.hosts["address"]; !ok {
					t.Fatal("capture was incorrectly filtered")
				}
			}
			f = testflow.TFlow()
			f.Request.Host = test.host
			f.Request.Port = test.port
			f.Request.Scheme = test.scheme
			f.Request.Path = "/matched"
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, f.Request.Headers.Get("Authorization")); diff != "" {
				t.Fatal(diff)
			}
			if test.auth[0] == "" && !f.Request.Headers.Has("Authorization") {
				t.Fatal("empty retained header was not injected")
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
	f.Request.Host = "host"
	f.Request.Headers.Set("Authorization", "synthetic-long")
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	retained := s.bytes
	f.Request.Host = "oversized"
	f.Request.Headers.Set("Authorization", strings.Repeat("x", maxJarBytes))
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal("overflow must not fail the flow", err)
	}
	f.Request.Host = "later"
	f.Request.Headers.Set("Authorization", "drop")
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if len(s.hosts) != 1 || s.bytes != retained || !s.overflow {
		t.Fatal("growing writes retained during overflow")
	}
	if strings.Count(logs.String(), "jar limit reached") != 1 {
		t.Fatal("warning emitted more than once")
	}
	f.Request.Host = "host"
	f.Request.Headers.Set("Authorization", "x")
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if s.overflow || s.bytes != len("hostx") {
		t.Fatal("shrinking overwrite failed to release capacity")
	}
	f.Request.Host = "later"
	f.Request.Headers.Set("Authorization", "keep")
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if len(s.hosts) != 2 {
		t.Fatal("capacity not restored")
	}
}

func TestHostCountBound(t *testing.T) {
	mgr, _, s := setup(t, new(".*"))
	f := testflow.TFlow()
	f.Request.Headers.Set("Authorization", "synthetic-long")
	for i := range maxJarHosts {
		f.Request.Host = fmt.Sprintf("host%d", i)
		if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
			t.Fatal(err)
		}
	}
	f.Request.Host = "extra"
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if len(s.hosts) != maxJarHosts || !s.overflow {
		t.Fatal("count bound not enforced")
	}
	f.Request.Host = "host0"
	f.Request.Headers.Set("Authorization", "x")
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if s.overflow {
		t.Fatal("shrinking overwrite did not reset overflow")
	}
}

func TestRetainedAcrossDisable(t *testing.T) {
	mgr, opts, _ := setup(t, new(".*"))
	f := testflow.TFlow()
	f.Request.Headers.Set("Authorization", "foo")
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []*string{nil, new(".*")} {
		if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"stickyauth": pattern}) }); err != nil {
			t.Fatal(err)
		}
	}
	f.Request.Headers.Del("Authorization")
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff("foo", f.Request.Headers.Get("Authorization")); diff != "" {
		t.Fatal(diff)
	}
}

func TestConcurrentDispatch(t *testing.T) {
	mgr, _, _ := setup(t, new(".*"))
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			f := testflow.TFlow()
			f.Request.Headers.Set("Authorization", "synthetic")
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Error(err)
			}
			f.Request.Headers.Del("Authorization")
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
	}{"stickyauth": {options.TypeOptStr, (*string)(nil), "Set sticky auth filter. Matched against requests."}}
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
	if s.Name() != "stickyauth" {
		t.Fatal(s.Name())
	}
}
