// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modifyheaders

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

// TestParseModifySpec ports upstream test_parse_modify_spec.
func TestParseModifySpec(t *testing.T) {
	tests := map[string]struct {
		option                    string
		regex                     bool
		subject, replacement, err string
	}{
		"error: incomplete":               {option: "/", err: "Invalid number of parameters"},
		"error: bad regex":                {option: "/[/two", regex: true, err: "Invalid regular expression"},
		"error: missing file":             {option: "/one/@nonexistent", err: "Invalid file path: nonexistent"},
		"success: filtered regex":         {option: "/foo/bar/voing", regex: true, subject: "bar", replacement: "voing"},
		"success: replacement separators": {option: "/foo/bar/vo/ing/", subject: "bar", replacement: "vo/ing/"},
		"success: match all":              {option: "/bar/voing", subject: "bar", replacement: "voing"},
		"success: escaped colon":          {option: `|X\x3aName|value\x3apart`, subject: "X:Name", replacement: "value:part"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			spec, err := ParseModifySpec(tt.option, tt.regex)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("parse error = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			replacement, err := spec.ReadReplacement()
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{tt.subject, tt.replacement}, []string{string(spec.Subject), string(replacement)}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func setup(t *testing.T, patterns []string) (*addon.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	cmds := command.NewManager()
	mgr := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(mgr.Close)
	if err := mgr.Add(t.Context(), New(opts)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"modify_headers": patterns}) }); err != nil {
		t.Fatal(err)
	}
	return mgr, opts
}

// TestModifyHeaders ports upstream test_modify_headers and every modify_headers documentation example.
func TestModifyHeaders(t *testing.T) {
	tests := map[string]struct {
		patterns         []string
		response         bool
		header, original string
		want             []string
	}{
		"success: request":                     {patterns: []string{"/~q/one/two", "/~s/one/three"}, header: "one", original: "xxx", want: []string{"two"}},
		"success: response":                    {patterns: []string{"/~q/one/two", "/~s/one/three"}, response: true, header: "one", original: "xxx", want: []string{"three"}},
		"success: repeated request":            {patterns: []string{"/~q/one/two", "/~q/one/three"}, header: "one", original: "xxx", want: []string{"two", "three"}},
		"success: repeated response":           {patterns: []string{"/~s/one/two", "/~s/one/three"}, response: true, header: "one", original: "xxx", want: []string{"two", "three"}},
		"success: removal request":             {patterns: []string{"/~q/one/", "/~s/one/"}, header: "one", original: "xxx"},
		"success: removal response":            {patterns: []string{"/~q/one/", "/~s/one/"}, response: true, header: "one", original: "xxx"},
		"success: unfiltered removal request":  {patterns: []string{"/one/"}, header: "one", original: "xxx"},
		"success: unfiltered removal response": {patterns: []string{"/one/"}, response: true, header: "one", original: "xxx"},
		"success: matching original header":    {patterns: []string{"/~hq ^user-agent:.+Mozilla.+$/user-agent/Definitely not Mozilla ;)"}, header: "user-agent", original: "Hello, it's me, Mozilla", want: []string{"Definitely not Mozilla ;)"}},
		"success: all filters before changes":  {patterns: []string{"/~hq ^user-agent:.*Mozilla/user-agent/first", "/~hq ^user-agent:.*Mozilla/user-agent/second"}, header: "user-agent", original: "Mozilla", want: []string{"first", "second"}},
		"docs: overwrite host":                 {patterns: []string{"/~q/Host/example.org"}, header: "Host", original: "old.example", want: []string{"example.org"}},
		"docs: add absent host":                {patterns: []string{"/~q & !~h Host:/Host/example.org"}, header: "Host", want: []string{"example.org"}},
		"docs: keep present host":              {patterns: []string{"/~q & !~h Host:/Host/example.org"}, header: "Host", original: "old.example", want: []string{"old.example"}},
		"docs: remove host":                    {patterns: []string{"/~q/Host/"}, header: "Host", original: "old.example"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _ := setup(t, tt.patterns)
			f := testflow.TFlow()
			hdrs := &f.Request.Headers
			if tt.response {
				f.Response = testflow.TResp()
				hdrs = &f.Response.Headers
			}
			hdrs.Del(tt.header)
			if tt.original != "" {
				hdrs.Add(tt.header, tt.original)
			}
			var hook addon.Hook = addon.RequestHeadersHook{Flow: f}
			if tt.response {
				hook = addon.ResponseHeadersHook{Flow: f}
			}
			if err := mgr.Hook(t.Context(), hook); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, hdrs.GetAll(tt.header)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestTaken ports both branches of upstream test_taken and adds inactive/error requests.
func TestTaken(t *testing.T) {
	tests := map[string]struct {
		response bool
		mutate   func(*flow.HTTPFlow)
		want     string
	}{
		"success: request active":    {want: "42"},
		"success: response active":   {response: true, want: "42"},
		"skip: request has response": {mutate: func(f *flow.HTTPFlow) { f.Response = testflow.TResp() }, want: "7"},
		"skip: request has error":    {mutate: func(f *flow.HTTPFlow) { f.Error = flow.NewError("failed") }, want: "7"},
		"skip: request inactive":     {mutate: func(f *flow.HTTPFlow) { f.Live = false }, want: "7"},
		"skip: response killed": {response: true, mutate: func(f *flow.HTTPFlow) {
			if err := f.Kill(); err != nil {
				t.Fatal(err)
			}
		}, want: "7"},
		"skip: response inactive": {response: true, mutate: func(f *flow.HTTPFlow) { f.Live = false }, want: "7"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _ := setup(t, []string{"/content-length/42"})
			f := testflow.TFlow()
			hdrs := &f.Request.Headers
			var hook addon.Hook = addon.RequestHeadersHook{Flow: f}
			if tt.response {
				f.Response = testflow.TResp()
				hdrs = &f.Response.Headers
				hook = addon.ResponseHeadersHook{Flow: f}
			}
			if tt.mutate != nil {
				tt.mutate(f)
			}
			if err := mgr.Hook(t.Context(), hook); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, hdrs.Get("content-length")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestReplacementFiles ports upstream test_simple/test_nonexistent and the documented user-agent file example.
func TestReplacementFiles(t *testing.T) {
	tests := map[string]struct {
		remove bool
		data   string
	}{
		"success: file replacement":           {data: "two"},
		"docs: user agent file":               {data: "custom user agent"},
		"error: file removed after configure": {remove: true, data: "two"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "replacement")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			mgr, _ := setup(t, []string{"/~q/User-Agent/@" + path})
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })
			if tt.remove {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			f := testflow.TFlow()
			f.Request.Headers.Set("User-Agent", "old")
			if err := mgr.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			var want []string
			if !tt.remove {
				want = []string{tt.data}
			}
			if diff := gocmp.Diff(want, f.Request.Headers.GetAll("User-Agent")); diff != "" {
				t.Fatal(diff)
			}
			if tt.remove && !strings.Contains(logs.String(), "Could not read replacement file:") {
				t.Fatalf("missing upstream warning: %s", logs.String())
			}
		})
	}
}

func TestFileSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, (16<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseModifySpec("|one|@"+path, false); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized file error = %v", err)
	}
}

// TestConfigure ports upstream test_configure, including option rollback.
func TestConfigure(t *testing.T) {
	mgr, opts := setup(t, []string{"/one/two"})
	if err := mgr.Do(t.Context(), func(ctx context.Context) error {
		return opts.Update(ctx, map[string]any{"modify_headers": []string{"/"}})
	}); err == nil || !strings.Contains(err.Error(), "Cannot parse modify_headers option") {
		t.Fatalf("configure error = %v", err)
	}
	f := testflow.TFlow()
	if err := mgr.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff("two", f.Request.Headers.Get("one")); diff != "" {
		t.Fatal(diff)
	}
}

func TestConcurrentDispatch(t *testing.T) {
	mgr, _ := setup(t, []string{"/one/two"})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			f := testflow.TFlow()
			if err := mgr.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
				t.Error(err)
				return
			}
			if diff := gocmp.Diff("two", f.Request.Headers.Get("one")); diff != "" {
				t.Error(diff)
			}
		})
	}
	workers.Wait()
}

func TestOptionsAndCommands(t *testing.T) {
	opts := options.New()
	cmds := command.NewManager()
	mgr := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(mgr.Close)
	if err := mgr.Add(t.Context(), New(opts)); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  options.Type
		def  []string
		help string
	}{
		"modify_headers": {options.TypeSeq, []string{}, `Header modify pattern of the form "[/flow-filter]/header-name/[@]header-value", where the separator can be any character. The @ allows to provide a file path that is used to read the header value string. An empty header-value removes existing header-name headers.`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := opts.Lookup(name)
			if !ok {
				t.Fatal("missing option")
			}
			if diff := gocmp.Diff([]any{tt.typ, tt.def, tt.help}, []any{opt.Type(), opt.Default(), opt.Help()}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	var names []string
	for name := range cmds.Commands() {
		names = append(names, name)
	}
	if len(names) != 0 {
		t.Fatalf("upstream declares no commands, got %v", names)
	}
}
