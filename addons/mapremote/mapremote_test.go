// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package mapremote

import (
	"context"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T, patterns []string) (*addon.Manager, *options.Manager, *MapRemote) {
	t.Helper()
	opts := options.New()
	mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	m := New(opts)
	if err := mgr.Add(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"map_remote": patterns}) }); err != nil {
		t.Fatal(err)
	}
	return mgr, opts, m
}

// TestConfigure ports upstream TestMapRemote.test_configure.
func TestConfigure(t *testing.T) {
	mgr, opts, _ := setup(t, []string{"one/two/three"})
	tests := map[string]struct{ pattern, message string }{
		"error: invalid pattern": {"/foo/+/three", "Cannot parse map_remote option /foo/+/three: Invalid regular expression '+'"},
		"error: incomplete":      {"/", "Invalid number of parameters (2 or 3 are expected)"},
		"error: invalid filter":  {"/~unknown/foo/bar", "invalid filter expression"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := mgr.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"map_remote": []string{test.pattern}})
			})
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("configure = %v, want %q", err, test.message)
			}
			if diff := gocmp.Diff([]string{"one/two/three"}, opts.Seq("map_remote")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestRequest ports upstream test_simple/test_host_header and the documented examples.
func TestRequest(t *testing.T) {
	tests := map[string]struct {
		patterns                          []string
		url, host, method, want, wantHost string
	}{
		"success: simple":      {patterns: []string{":example.org/images/:mitmproxy.org/img/"}, url: "https://example.org/images/test.jpg", want: "https://mitmproxy.org/img/test.jpg"},
		"success: host header": {patterns: []string{"|http://[^/]+|http://example.com:4444"}, url: "http://example.org/example", host: "example.org", want: "http://example.com:4444/example", wantHost: "example.com:4444"},
		"success: unmatched pretty host leaves target alone":  {patterns: []string{"|never|example.com"}, url: "http://127.0.0.1/example", host: "example.org", want: "http://127.0.0.1/example", wantHost: "example.org"},
		"success: unchanged substitution leaves target alone": {patterns: []string{"|example.org|example.org"}, url: "http://127.0.0.1/example", host: "example.org", want: "http://127.0.0.1/example", wantHost: "example.org"},
		"success: ordered rewrites":                           {patterns: []string{":example.org:example.net", ":example.net:mitmproxy.org"}, url: "https://example.org/a", want: "https://mitmproxy.org/a"},
		"success: python groups":                              {patterns: []string{`|https://example.org/(.*)|https://mitmproxy.org/\1`}, url: "https://example.org/a", want: "https://mitmproxy.org/a"},
		"success: python named groups":                        {patterns: []string{`|https://example.org/(?P<path>.*)|https://mitmproxy.org/\g<path>`}, url: "https://example.org/a", want: "https://mitmproxy.org/a"},
		"docs: jpg mapping":                                   {patterns: []string{`|.*\.jpg$|https://placedog.net/640/480?random`}, url: "https://example.org/test.jpg", want: "https://placedog.net/640/480?random"},
		"docs: GET mapping":                                   {patterns: []string{"|~m GET|//example.org/|//mitmproxy.org/"}, url: "https://example.org/images/test.jpg", method: "GET", want: "https://mitmproxy.org/images/test.jpg"},
		"docs: GET filter excludes POST":                      {patterns: []string{"|~m GET|//example.org/|//mitmproxy.org/"}, url: "https://example.org/images/test.jpg", method: "POST", want: "https://example.org/images/test.jpg"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, test.patterns)
			f := testflow.TFlow()
			if err := f.Request.SetURL(test.url); err != nil {
				t.Fatal(err)
			}
			if test.host != "" {
				f.Request.Headers.Set("Host", test.host)
			}
			if test.method != "" {
				f.Request.Method = test.method
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, f.Request.URL()); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(test.wantHost, f.Request.Headers.Get("Host")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestTaken ports upstream test_is_killed and confirms the response/error/live guards.
func TestTaken(t *testing.T) {
	tests := map[string]struct {
		mutate func(*flow.HTTPFlow)
		want   string
	}{
		"skip: killed": {mutate: func(f *flow.HTTPFlow) {
			if err := f.Kill(); err != nil {
				t.Fatal(err)
			}
		}, want: "example.org"},
		"skip: failed":                   {mutate: func(f *flow.HTTPFlow) { f.Error = flow.NewError("failed") }, want: "example.org"},
		"skip: answered":                 {mutate: func(f *flow.HTTPFlow) { f.Response = testflow.TResp() }, want: "example.org"},
		"skip: inactive":                 {mutate: func(f *flow.HTTPFlow) { f.Live = false }, want: "example.org"},
		"success: live replay rewritten": {mutate: func(f *flow.HTTPFlow) { f.IsReplay = new("request") }, want: "mitmproxy.org"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, []string{":example.org:mitmproxy.org"})
			f := testflow.TFlow()
			if err := f.Request.SetURL("https://example.org/images/test.jpg"); err != nil {
				t.Fatal(err)
			}
			test.mutate(f)
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, f.Request.Host); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestInvalidTransformation(t *testing.T) {
	tests := map[string]struct{ pattern string }{
		"error: invalid output URL":     {"|.*|not-a-url"},
		"error: invalid group template": {`|example.org|\g<missing>`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, m := setup(t, []string{test.pattern})
			f := testflow.TFlow()
			before := f.Request.Clone()
			err := mgr.Do(t.Context(), func(ctx context.Context) error { return m.Request(ctx, f) })
			if err == nil {
				t.Fatal("invalid transformation succeeded")
			}
			if diff := gocmp.Diff(before, f.Request); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestOptionsAndCommands(t *testing.T) {
	opts := options.New()
	cmds := command.NewManager()
	mgr := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(mgr.Close)
	m := New(opts)
	if err := mgr.Add(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{
		"map_remote": {options.TypeSeq, []string{}, `Map remote resources to another remote URL using a pattern of the form "[/flow-filter]/url-regex/replacement", where the separator can be any character.`},
	}
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
	if m.Name() != "mapremote" {
		t.Fatal(m.Name())
	}
}

func TestConcurrentDispatch(t *testing.T) {
	mgr, _, _ := setup(t, []string{":address:example.com"})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 16 {
				f := testflow.TFlow()
				if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
					t.Error(err)
				}
				if f.Request.Host != "example.com" {
					t.Error(f.Request.Host)
				}
			}
		})
	}
	wg.Wait()
}
