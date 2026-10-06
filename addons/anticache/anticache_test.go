// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package anticache

import (
	"context"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// TestSimple ports upstream test_simple with repeated conditional headers.
func TestSimple(t *testing.T) {
	tests := map[string]struct{ enabled bool }{"skip: disabled": {}, "success: enabled": {true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
			t.Cleanup(mgr.Close)
			if err := mgr.Add(t.Context(), New(opts)); err != nil {
				t.Fatal(err)
			}
			if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"anticache": test.enabled}) }); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow()
			f.Response = testflow.TResp()
			f.Request.Headers.Set("If-Modified-Since", "test")
			f.Request.Headers.Add("if-modified-since", "test2")
			f.Request.Headers.Set("If-None-Match", "test")
			f.Request.Headers.Add("if-none-match", "test2")
			f.Request.Headers.Set("Cache-Control", "no-cache")
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]bool{!test.enabled, !test.enabled}, []bool{f.Request.Headers.Has("if-modified-since"), f.Request.Headers.Has("if-none-match")}); diff != "" {
				t.Fatal(diff)
			}
			if f.Request.Headers.Get("Cache-Control") != "no-cache" {
				t.Fatal("unrelated header modified")
			}
		})
	}
}

func TestOptionsAndCommands(t *testing.T) {
	opts := options.New()
	cmds := command.NewManager()
	mgr := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(mgr.Close)
	a := New(opts)
	if err := mgr.Add(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{"anticache": {options.TypeBool, false, "Strip out request headers that might cause the server to return 304-not-modified."}}
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
	if a.Name() != "anticache" {
		t.Fatal(a.Name())
	}
}

func TestConcurrentDispatch(t *testing.T) {
	opts := options.New()
	mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	if err := mgr.Add(t.Context(), New(opts)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			f := testflow.TFlow()
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Error(err)
			}
		})
		wg.Go(func() {
			if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"anticache": true}) }); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}
