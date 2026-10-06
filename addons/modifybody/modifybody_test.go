// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modifybody

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
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

func setup(t *testing.T, patterns []string) (*addon.Manager, *options.Manager, *ModifyBody) {
	t.Helper()
	opts := options.New()
	if err := opts.Add(t.Context(), "stream_large_bodies", options.TypeOptStr, (*string)(nil), "Streaming threshold."); err != nil {
		t.Fatal(err)
	}
	mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	m := New(opts)
	if err := mgr.Add(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"modify_body": patterns}) }); err != nil {
		t.Fatal(err)
	}
	return mgr, opts, m
}

// TestConfigure ports upstream TestModifyBody.test_configure.
func TestConfigure(t *testing.T) {
	mgr, opts, _ := setup(t, []string{"one/two/three"})
	tests := map[string]struct{ pattern, error string }{
		"error: incomplete specification": {pattern: "/", error: "Cannot parse modify_body option /:"},
		"error: invalid regex":            {pattern: "/[/x", error: "Invalid regular expression"},
		"error: missing file":             {pattern: "/a/@nonexistent", error: "Invalid file path:"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := mgr.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"modify_body": []string{test.pattern}})
			})
			if err == nil || !strings.Contains(err.Error(), test.error) {
				t.Fatalf("configure error = %v, want %q", err, test.error)
			}
			if diff := gocmp.Diff([]string{"one/two/three"}, opts.Seq("modify_body")); diff != "" {
				t.Fatalf("option rollback (-want +got):\n%s", diff)
			}
		})
	}
}

// TestModifyBody ports upstream test_simple, test_order and test_backslash_in_replacement.
func TestModifyBody(t *testing.T) {
	tests := map[string]struct {
		patterns    []string
		input, want string
		response    bool
	}{
		"success: request":                                {patterns: []string{"/~q/foo/bar", "/~s/foo/bar"}, input: "foo", want: "bar"},
		"success: response":                               {patterns: []string{"/~q/foo/bar", "/~s/foo/bar"}, input: "foo", want: "bar", response: true},
		"success: ordered changes":                        {patterns: []string{"/foo/bar", "/bar/baz", "/foo/oh noes!", "/bar/oh noes!"}, input: "foo", want: "baz"},
		"success: escaped request replacement":            {patterns: []string{`/~q/foo/bar\x00`, `/~s/foo/bar\n`}, input: "foo", want: "bar\x00"},
		"success: escaped response replacement":           {patterns: []string{`/~q/foo/bar\x00`, `/~s/foo/bar\n`}, input: "foo", want: "bar\n", response: true},
		"success: replacement backreferences are literal": {patterns: []string{`/(foo)/\\1`}, input: "foo", want: `\1`},
		"success: DOTALL":                                 {patterns: []string{`/a.*z/x`}, input: "a\nz", want: "x"},
		"success: all matches":                            {patterns: []string{"/foo/bar"}, input: "foo foo", want: "bar bar"},
		"success: binary bytes":                           {patterns: []string{`/\xff/x`}, input: "\xff\xfe", want: "x\xfe"},
		"success: final newline preserved":                {patterns: []string{"/foo$/bar"}, input: "foo\n", want: "bar\n"},
		"success: later filter observes changed body":     {patterns: []string{"/foo/bar", "/~b bar/bar/baz"}, input: "foo", want: "baz"},
		"success: empty present body":                     {patterns: []string{"/^$/x"}, input: "", want: "x"},
		"docs: request body replacement":                  {patterns: []string{"/~q/foo/bar"}, input: "foo", want: "bar"},
		"docs: request filter excludes response":          {patterns: []string{"/~q/foo/bar"}, input: "foo", want: "foo", response: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, test.patterns)
			f := testflow.TFlow()
			message := &f.Request.Message
			var hook addon.Hook = addon.RequestHook{Flow: f}
			if test.response {
				f.Response = testflow.TResp()
				message = &f.Response.Message
				hook = addon.ResponseHook{Flow: f}
			}
			message.SetContent([]byte(test.input))
			if err := mgr.Hook(t.Context(), hook); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, string(message.ContentOrRaw())); diff != "" {
				t.Fatalf("body (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTaken ports upstream test_taken and adds inactive/error and streamed bodies.
func TestTaken(t *testing.T) {
	tests := map[string]struct {
		response bool
		mutate   func(*flow.HTTPFlow)
		want     string
	}{
		"success: active request":        {want: "bar"},
		"success: active response":       {response: true, want: "bar"},
		"skip: already answered request": {mutate: func(f *flow.HTTPFlow) { f.Response = testflow.TResp() }, want: "foo"},
		"skip: failed request":           {mutate: func(f *flow.HTTPFlow) { f.Error = flow.NewError("failed") }, want: "foo"},
		"skip: inactive request":         {mutate: func(f *flow.HTTPFlow) { f.Live = false }, want: "foo"},
		"skip: killed response": {response: true, mutate: func(f *flow.HTTPFlow) {
			if err := f.Kill(); err != nil {
				t.Fatal(err)
			}
		}, want: "foo"},
		"skip: inactive response": {response: true, mutate: func(f *flow.HTTPFlow) { f.Live = false }, want: "foo"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, []string{"/foo/bar"})
			f := testflow.TFlow()
			message := &f.Request.Message
			var hook addon.Hook = addon.RequestHook{Flow: f}
			if test.response {
				f.Response = testflow.TResp()
				message = &f.Response.Message
				hook = addon.ResponseHook{Flow: f}
			}
			message.SetContent([]byte("foo"))
			if test.mutate != nil {
				test.mutate(f)
			}
			if err := mgr.Hook(t.Context(), hook); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, string(message.ContentOrRaw())); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	t.Run("skip: streamed body remains missing", func(t *testing.T) {
		mgr, _, _ := setup(t, []string{"/./x"})
		f := testflow.TFlow()
		f.Request.RawContent = nil
		if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
			t.Fatal(err)
		}
		if f.Request.RawContent != nil {
			t.Fatal("streamed body became present")
		}
	})
}

// TestReplacementFiles ports TestModifyBodyFile.test_simple/test_nonexistent and the documented @file example.
func TestReplacementFiles(t *testing.T) {
	tests := map[string]struct {
		remove bool
		data   string
	}{
		"success: file":                    {data: "bar"},
		"success: file bytes stay literal": {data: `\g<1>`},
		"error: removed after configure":   {remove: true, data: "bar"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "replacement")
			if err := os.WriteFile(file, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			mgr, _, _ := setup(t, []string{"/~q/foo/@" + file})
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(old) })
			if test.remove {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			}
			f := testflow.TFlow()
			f.Request.SetContent([]byte("foo"))
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			want := test.data
			if test.remove {
				want = "foo"
				if !strings.Contains(logs.String(), "Could not read replacement file:") {
					t.Fatal(logs.String())
				}
			}
			if diff := gocmp.Diff(want, string(f.Request.ContentOrRaw())); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	t.Run("docs: home-relative file", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "xss-exploit"), []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		mgr, _, _ := setup(t, []string{":~q:foo:@~/xss-exploit"})
		f := testflow.TFlow()
		f.Request.SetContent([]byte("foo"))
		if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff("replacement", string(f.Request.ContentOrRaw())); diff != "" {
			t.Fatal(diff)
		}
	})
}

// TestWarnConflict ports upstream test_warn_conflict.
func TestWarnConflict(t *testing.T) {
	mgr, opts, _ := setup(t, nil)
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	if err := mgr.Do(t.Context(), func(ctx context.Context) error {
		return opts.Update(ctx, map[string]any{"stream_large_bodies": new("3m"), "modify_body": []string{"/foo/bar"}})
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "Both modify_body and stream_large_bodies are active. Streamed bodies will not be modified.") {
		t.Fatal(logs.String())
	}
	logs.Reset()
	if err := mgr.Do(t.Context(), func(ctx context.Context) error {
		return opts.Update(ctx, map[string]any{"stream_large_bodies": new("4m")})
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "Streamed bodies will not be modified.") {
		t.Fatal("changing streaming option did not warn")
	}
}

func TestCompressedContent(t *testing.T) {
	mgr, _, m := setup(t, []string{"/foo/longer"})
	f := testflow.TFlow()
	f.Request.SetContent([]byte("foo"))
	if err := f.Request.Encode("gzip"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if f.Request.Headers.Get("content-encoding") != "gzip" {
		t.Fatal("compression was lost")
	}
	if diff := gocmp.Diff("longer", string(f.Request.ContentOrRaw())); diff != "" {
		t.Fatal(diff)
	}
	f.Request.RawContent = []byte("invalid gzip")
	before := f.Request.Message
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return m.Request(ctx, f) }); err == nil {
		t.Fatal("invalid content encoding did not return an error")
	}
	if diff := gocmp.Diff(before, f.Request.Message); diff != "" {
		t.Fatalf("failed decode changed message: %s", diff)
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
		"modify_body": {options.TypeSeq, []string{}, `Replacement pattern of the form "[/flow-filter]/regex/[@]replacement", where the separator can be any character. The @ allows to provide a file path that is used to read the replacement string.`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o, ok := opts.Lookup(name)
			if !ok {
				t.Fatal("option missing")
			}
			if diff := gocmp.Diff([]any{test.typ, test.def, test.help}, []any{o.Type(), o.Default(), o.Help()}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for name := range cmds.Commands() {
		t.Errorf("unexpected command %s; upstream declares none", name)
	}
	if m.Name() != "modifybody" {
		t.Fatal(m.Name())
	}
}

func TestConcurrentDispatch(t *testing.T) {
	mgr, _, _ := setup(t, []string{"/foo/bar"})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 16 {
				f := testflow.TFlow()
				f.Request.SetContent([]byte("foo"))
				if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
					t.Error(err)
					return
				}
				if string(f.Request.ContentOrRaw()) != "bar" {
					t.Error("body was not rewritten")
					return
				}
			}
		})
	}
	wg.Wait()
}
