// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package blocklist

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
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T, patterns []string) (*addon.Manager, *options.Manager, *BlockList) {
	t.Helper()
	opts := options.New()
	mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(mgr.Close)
	b := New(opts)
	if err := mgr.Add(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"block_list": patterns}) }); err != nil {
		t.Fatal(err)
	}
	return mgr, opts, b
}

// TestParseSpec ports test_parse_spec_err, adding Python integer syntax cases.
func TestParseSpec(t *testing.T) {
	tests := map[string]struct {
		option, message string
		want            int
	}{
		"error: too many":             {"/~u index.html/TOOMANY/300", "Invalid number of parameters (2 are expected)", 0},
		"error: filter":               {":~d ~d ~d:200", "invalid filter expression", 0},
		"error: status":               {"/~u index.html/abc", "Invalid HTTP status code: abc", 0},
		"error: empty":                {"", "Invalid number of parameters", 0},
		"error: empty filter":         {"//404", "empty filter expression", 0},
		"error: separator in status":  {":.*:4:04", "Invalid number of parameters", 0},
		"error: misplaced underscore": {":.*:4__04", "Invalid HTTP status code", 0},
		"error: size suffix":          {":.*:4k", "Invalid HTTP status code", 0},
		"error: overflowing status":   {":.*:9223372036854775808", "Invalid HTTP status code", 0},
		"success: negative status":    {":.*:-1", "", -1},
		"success: Unicode separator":  {"€.*€404", "", 404},
		"success: whitespace":         {":.*: +404 ", "", 404},
		"success: underscores":        {":.*:4_0_4", "", 404},
		"success: Unicode digits":     {":.*:٤٠٤", "", 404},
		"success: arbitrary status":   {":.*:999", "", 999},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r, err := parse(t.Context(), test.option)
			if test.message != "" {
				if err == nil || !strings.Contains(err.Error(), test.message) {
					t.Fatalf("parse=%v, want %q", err, test.message)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, r.status); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestBlock ports all test_block vectors, uppercase_header_values and mixedcase_header_names.
func TestBlock(t *testing.T) {
	tests := map[string]struct {
		pattern, url, header, value string
		status                      int
	}{
		"success: matching host":           {":~u example.org:404", "https://example.org/images/test.jpg", "", "", 404},
		"skip: host mismatch":              {":~u example.com:404", "https://example.org/images/test.jpg", "", "", 0},
		"success: case insensitive":        {":~u test:404", "https://example.org/images/TEST.jpg", "", "", 404},
		"skip: negation":                   {"/!jpg/418", "https://example.org/images/test.jpg", "", "", 0},
		"success: negation":                {"/!png/418", "https://example.org/images/test.jpg", "", "", 418},
		"success: uppercase path":          {"|~u /DATA|500", "https://example.org/DATA", "", "", 500},
		"success: lowercase path":          {"|~u /ASSETS|501", "https://example.org/assets", "", "", 501},
		"success: uppercase matching":      {"|~u /ping|201", "https://example.org/PING", "", "", 201},
		"success: uppercase header values": {`|~hq Cookie:\sfoo=BAR|403`, "https://example.org/robots.txt", "Cookie", "foo=BAR; key1=value1", 403},
		"success: mixedcase header names":  {`|~hq User-Agent:\scurl|401`, "https://example.org/products/123", "user-agent", "curl/8.11.1", 401},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, []string{test.pattern})
			f := testflow.TFlow()
			if err := f.Request.SetURL(test.url); err != nil {
				t.Fatal(err)
			}
			if test.header != "" {
				f.Request.Headers.Set(test.header, test.value)
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			got := 0
			if f.Response != nil {
				got = f.Response.StatusCode
			}
			if diff := gocmp.Diff(test.status, got); diff != "" {
				t.Fatal(diff)
			}
			marked, _ := f.Metadata.Get("blocklisted")
			if test.status != 0 {
				if marked != true {
					t.Fatal("missing metadata")
				}
				if string(f.Response.RawContent) != "" || f.Response.Headers.Get("Server") != version.String() {
					t.Fatal("invalid empty block response")
				}
			} else if marked != nil {
				t.Fatal("unmatched flow marked")
			}
		})
	}
}

// TestKill ports test_special_kill_status_closes_connection and test_already_handled.
func TestKill(t *testing.T) {
	tests := map[string]struct {
		patterns       []string
		mutate         func(*flow.HTTPFlow)
		status         int
		killed, marked bool
	}{
		"success: kill": {patterns: []string{":.*:444"}, killed: true, marked: true},
		"skip: already killed": {patterns: []string{"/.*/404"}, mutate: func(f *flow.HTTPFlow) {
			if err := f.Kill(); err != nil {
				t.Fatal(err)
			}
		}, killed: true},
		"skip: answered":                     {patterns: []string{"/.*/404"}, mutate: func(f *flow.HTTPFlow) { f.Response = testflow.TResp() }, status: 200},
		"skip: inactive":                     {patterns: []string{"/.*/404"}, mutate: func(f *flow.HTTPFlow) { f.Live = false }},
		"success: last matching status wins": {patterns: []string{":.*:403", ":.*:404"}, status: 404, marked: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mgr, _, _ := setup(t, test.patterns)
			f := testflow.TFlow()
			if test.mutate != nil {
				test.mutate(f)
			}
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			status := 0
			if f.Response != nil {
				status = f.Response.StatusCode
			}
			killed := f.Error != nil && f.Error.Msg == flow.KilledMessage
			marked, _ := f.Metadata.Get("blocklisted")
			if diff := gocmp.Diff([]any{test.status, test.killed, test.marked}, []any{status, killed, marked == true}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// TestConfigureError ports upstream test_configure_err.
func TestConfigureError(t *testing.T) {
	mgr, opts, _ := setup(t, []string{"/.*/404"})
	err := mgr.Do(t.Context(), func(ctx context.Context) error {
		return opts.Update(ctx, map[string]any{"block_list": []string{"lalelu"}})
	})
	if err == nil || !strings.Contains(err.Error(), "Cannot parse block_list option lalelu:") {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"/.*/404"}, opts.Seq("block_list")); diff != "" {
		t.Fatal(diff)
	}
}

func TestConcurrentDispatch(t *testing.T) {
	mgr, opts, _ := setup(t, []string{":.*:404"})
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			f := testflow.TFlow()
			if err := mgr.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Error(err)
				return
			}
			if f.Response == nil || f.Response.StatusCode != 404 {
				t.Error("matching request was not blocked")
			}
		})
		wg.Go(func() {
			if err := mgr.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"block_list": []string{":.*:404"}})
			}); err != nil {
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
	b := New(opts)
	if err := mgr.Add(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{"block_list": {options.TypeSeq, []string{}, `Block matching requests and return an empty response with the specified HTTP status. Option syntax is "/flow-filter/status-code", where flow-filter describes which requests this rule should be applied to and status-code is the HTTP status code to return for blocked requests. The separator ("/" in the example) can be any character. Setting a non-standard status code of 444 will close the connection without sending a response.`}}
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
	if b.Name() != "blocklist" {
		t.Fatal(b.Name())
	}
}
