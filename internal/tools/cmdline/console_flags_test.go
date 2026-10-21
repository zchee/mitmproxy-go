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

	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/addons/intercept"
	"github.com/zchee/mitmproxy-go/addons/termlog"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/tools/web"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func consoleProfileMaster(t *testing.T) *master.Master {
	t.Helper()
	m := master.New(master.Config{})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if err := m.Options.Update(ctx, map[string]any{"confdir": t.TempDir()}); err != nil {
			return err
		}
		return m.Options.Add(ctx, "flow_detail", options.TypeInt, 1, "Dump verbosity.")
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Add(t.Context(), termlog.New(m.Options, io.Discard, m.ShutdownWithError), core.New(m.Addons), intercept.New(m.Options), view.New(m.Addons), &console.ConsoleAddon{}, &web.WebAddon{}); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMitmproxyFlags(t *testing.T) {
	t.Run("profiles", func(t *testing.T) {
		tests := map[string]struct{}{"console_flags": {}, "no_positionals": {}, "quiet_verbose": {}, "preserve_dump": {}, "preserve_web": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				m := consoleProfileMaster(t)
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
					tests := map[string]struct {
						args  []string
						level string
					}{
						"quiet":        {[]string{"-q"}, "error"},
						"verbose":      {[]string{"-v"}, "debug"},
						"verbose wins": {[]string{"-q", "-v"}, "debug"},
						"options":      {[]string{"--options"}, "error"},
						"commands":     {[]string{"--commands"}, "error"},
					}
					for name, test := range tests {
						if err := run(NewConsole(opts, "test"), test.args...); err != nil {
							t.Fatalf("%s: %v", name, err)
						}
						if opts.Str("termlog_verbosity") != test.level || opts.Int("flow_detail") != 1 {
							t.Fatalf("%s changed an unrelated dump option: level=%q detail=%d", name, opts.Str("termlog_verbosity"), opts.Int("flow_detail"))
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
					if cmd.Name() != "mitmweb" || opts.Int("web_port") != 9090 || opts.Bool("web_open_browser") || opts.Str("termlog_verbosity") != "debug" || opts.Int("flow_detail") != 1 {
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
