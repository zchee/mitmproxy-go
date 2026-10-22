// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package cmdline

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"

	"github.com/zchee/mitmproxy-go/internal/tools/web"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMitmwebFlags(t *testing.T) {
	tests := map[string]struct {
		args   []string
		config string
		want   map[string]any
		err    bool
	}{
		"listener":                     {args: []string{"--web-host", "::1", "--web-port", "9000", "--no-web-open-browser"}, want: map[string]any{"web_host": "::1", "web_port": 9000, "web_open_browser": false}},
		"open_browser":                 {args: []string{"--web-open-browser"}, want: map[string]any{"web_open_browser": true}},
		"intercept":                    {args: []string{"--intercept", "~u example"}, want: map[string]any{"intercept": new("~u example"), "intercept_active": true}},
		"precedence":                   {args: []string{"--set", "web_port=1", "--web-port", "3"}, config: "web_port: 2\nweb_theme: dark\n", want: map[string]any{"web_port": 3, "web_theme": "dark"}},
		"quiet":                        {args: []string{"-q"}, want: map[string]any{"termlog_verbosity": "error"}},
		"verbose":                      {args: []string{"-v"}, want: map[string]any{"termlog_verbosity": "debug"}},
		"options":                      {args: []string{"--options"}, want: map[string]any{"termlog_verbosity": "error"}},
		"commands":                     {args: []string{"--commands"}, want: map[string]any{"termlog_verbosity": "error"}},
		"all_via_set":                  {args: []string{"--set", "web_theme=light", "--set", "web_debug=true", "--set", "web_columns=method"}, want: map[string]any{"web_theme": "light", "web_debug": true, "web_columns": []string{"method"}}},
		"conflicting_browser":          {args: []string{"--web-open-browser", "--no-web-open-browser"}, err: true},
		"conflicting_browser_reversed": {args: []string{"--no-web-open-browser", "--web-open-browser"}, err: true},
		"dump_detail_rejected":         {args: []string{"--flow-detail", "1"}, err: true},
		"positional_rejected":          {args: []string{"~u", "example"}, err: true},
		"dedicated_theme_rejected":     {args: []string{"--web-theme", "dark"}, err: true},
		"dedicated_password_rejected":  {args: []string{"--web-password", "fixture"}, err: true},
		"scripts_accepted":             {args: []string{"-s", "addon.star"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			confdir := t.TempDir()
			if name == "scripts_accepted" {
				path := filepath.Join(confdir, "addon.star")
				if err := os.WriteFile(path, []byte("def request(f):\n    f.comment = \"loaded\"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				tt.args = []string{"-s", path}
				tt.want = map[string]any{"scripts": []string{path}}
			}
			if err := opts.Update(t.Context(), map[string]any{"confdir": confdir}); err != nil {
				t.Fatal(err)
			}
			if tt.config != "" {
				if err := os.WriteFile(filepath.Join(confdir, "config.yaml"), []byte(tt.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			m, err := web.New(t.Context(), web.Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard, WithTermlog: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
					t.Error(err)
				}
			})
			cmd := NewWeb(opts, "test-version")
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs(tt.args)
			cmd.RunE = func(c *cobra.Command, _ []string) error { return Apply(t.Context(), c, opts, m.Do) }
			err = cmd.ExecuteContext(t.Context())
			if (err != nil) != tt.err {
				t.Fatalf("args=%q error=%v want_error=%t", tt.args, err, tt.err)
			}
			for name, want := range tt.want {
				if diff := gocmp.Diff(want, opts.Current(name)); diff != "" {
					t.Fatalf("%s (-want +got):\n%s", name, diff)
				}
			}
			if m.WebAddr() != nil {
				t.Fatal("flag processing opened a listener")
			}
		})
	}
	t.Run("completions", func(t *testing.T) {
		tests := map[string]struct{}{"registered_flags": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				opts := options.New()
				m, err := web.New(t.Context(), web.Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard, WithTermlog: true})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
						t.Error(err)
					}
				})
				cmd := NewWeb(opts, "test")
				var output bytes.Buffer
				if err := cmd.GenBashCompletion(&output); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"--web-open-browser", "--no-web-open-browser", "--web-port", "--web-host", "--intercept"} {
					if !strings.Contains(output.String(), name) {
						t.Fatalf("missing completion %s", name)
					}
				}
				if strings.Contains(output.String(), "--flow-detail") {
					t.Fatal("dump flag leaked into completion")
				}
			})
		}
	})
}
