// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package cmdline

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"

	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
	"github.com/zchee/mitmproxy-go/internal/tools/web"
	"github.com/zchee/mitmproxy-go/master"
)

func consoleProfileMaster(t *testing.T, profile string) *master.Master {
	t.Helper()
	var base *master.Master
	var closeFrontend func(context.Context) error
	switch profile {
	case "preserve_dump":
		m, err := dump.New(t.Context(), dump.Config{Stdout: io.Discard, Stderr: io.Discard, WithTermlog: true, WithDumper: true})
		if err != nil {
			t.Fatal(err)
		}
		base, closeFrontend = m.Master, m.Close
	case "preserve_web":
		m, err := web.New(t.Context(), web.Config{Stdout: io.Discard, Stderr: io.Discard, WithTermlog: true})
		if err != nil {
			t.Fatal(err)
		}
		base, closeFrontend = m.Master, m.Close
	default:
		m, err := console.New(t.Context(), console.Config{Stdout: io.Discard, Stderr: io.Discard})
		if err != nil {
			t.Fatal(err)
		}
		base, closeFrontend = m.Master, m.Close
	}
	t.Cleanup(func() {
		if err := closeFrontend(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	if err := base.Do(t.Context(), func(ctx context.Context) error {
		return base.Options.Update(ctx, map[string]any{"confdir": t.TempDir()})
	}); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestMitmproxyFlags(t *testing.T) {
	t.Run("profiles", func(t *testing.T) {
		tests := map[string]struct{}{"console_flags": {}, "no_positionals": {}, "quiet_verbose": {}, "preserve_dump": {}, "preserve_web": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				m := consoleProfileMaster(t, name)
				opts := m.Options
				run := func(cmd *cobra.Command, args ...string) error {
					cmd.SetOut(io.Discard)
					cmd.SetErr(io.Discard)
					cmd.SilenceErrors, cmd.SilenceUsage = true, true
					cmd.SetArgs(args)
					cmd.RunE = func(cmd *cobra.Command, _ []string) error { return Apply(t.Context(), cmd, opts, m.Do) }
					return cmd.ExecuteContext(t.Context())
				}
				switch name {
				case "console_flags":
					cmd := NewConsole(opts, "test")
					if err := run(cmd, "--console-layout", "vertical", "--no-console-layout-headers", "--intercept", "~u example", "--view-filter", "~m GET"); err != nil {
						t.Fatal(err)
					}
					for key, expected := range map[string]any{"console_layout": "vertical", "console_layout_headers": false, "intercept": new("~u example"), "view_filter": new("~m GET")} {
						if diff := cmp.Diff(expected, opts.Current(key)); diff != "" {
							t.Fatalf("%s (-want +got): %s", key, diff)
						}
					}
					if cmd.Name() != "mitmproxy" {
						t.Fatalf("console command name=%q", cmd.Name())
					}
					var completion bytes.Buffer
					if err := cmd.GenBashCompletion(&completion); err != nil {
						t.Fatal(err)
					}
					for _, flag := range []string{"console-layout", "console-layout-headers", "no-console-layout-headers", "intercept", "view-filter"} {
						if cmd.Flags().Lookup(flag) == nil || !strings.Contains(completion.String(), "--"+flag) {
							t.Fatalf("console flag/completion missing: %s", flag)
						}
					}
					for _, flag := range []string{"flow-detail", "web-port", "web-host", "web-open-browser", "console-mouse", "console-palette"} {
						if cmd.Flags().Lookup(flag) != nil {
							t.Fatalf("unsupported dedicated console flag leaked: %s", flag)
						}
					}
				case "no_positionals":
					tests := map[string]struct{ args []string }{
						"positional filter":       {[]string{"~u", "example"}},
						"dump-only flag":          {[]string{"--flow-detail", "4"}},
						"web-only flag":           {[]string{"--web-port", "9090"}},
						"no dedicated mouse flag": {[]string{"--console-mouse"}},
						"invalid layout":          {[]string{"--console-layout", "invalid"}},
					}
					for name, test := range tests {
						if err := run(NewConsole(opts, "test"), test.args...); err == nil {
							t.Fatalf("%s accepted args %q", name, test.args)
						}
					}
				case "quiet_verbose":
					tests := map[string]struct{ args []string }{
						"quiet":    {[]string{"-q"}},
						"verbose":  {[]string{"-v"}},
						"both":     {[]string{"-q", "-v"}},
						"options":  {[]string{"--options"}},
						"commands": {[]string{"--commands"}},
					}
					for name, test := range tests {
						if err := run(NewConsole(opts, "test"), test.args...); err != nil {
							t.Fatalf("%s: %v", name, err)
						}
						if opts.Has("termlog_verbosity") || opts.Has("flow_detail") {
							t.Fatalf("%s invented a terminal-log or dump-detail option in the console", name)
						}
					}
				case "preserve_dump":
					cmd := New(opts, "test")
					args := []string{"~u", "example", "--flow-detail", "4"}
					if err := run(cmd, args...); err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(args, cmd.Flags().Args()); diff != "" {
						t.Fatal("dump remainder changed: " + diff)
					}
					if cmd.Name() != "mitmdump" || cmd.Flags().Lookup("flow-detail") == nil || cmd.Flags().Lookup("console-layout") != nil {
						t.Fatal("dump profile vocabulary changed")
					}
					if err := run(New(opts, "test"), "-q", "--flow-detail", "4"); err != nil {
						t.Fatal(err)
					}
					if opts.Int("flow_detail") != 0 {
						t.Fatal("dump quiet/detail precedence changed")
					}
				case "preserve_web":
					cmd := NewWeb(opts, "test")
					if err := run(cmd, "--web-port", "9090", "--no-web-open-browser", "--intercept", "~u example", "-v"); err != nil {
						t.Fatal(err)
					}
					if cmd.Name() != "mitmweb" || opts.Int("web_port") != 9090 || opts.Bool("web_open_browser") || opts.Str("termlog_verbosity") != "debug" || opts.Has("flow_detail") {
						t.Fatal("web profile options/quiet behavior changed")
					}
					if cmd.Flags().Lookup("console-layout") != nil || cmd.Flags().Lookup("flow-detail") != nil {
						t.Fatal("non-web flag leaked into web profile")
					}
					if err := run(NewWeb(opts, "test"), "~u", "example"); err == nil {
						t.Fatal("web positional filter was accepted")
					}
				}
			})
		}
	})
}
