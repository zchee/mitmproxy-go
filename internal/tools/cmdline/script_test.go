// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package cmdline

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"

	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
	"github.com/zchee/mitmproxy-go/internal/tools/web"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func TestScriptFlags(t *testing.T) {
	t.Run("profiles", func(t *testing.T) {
		tests := map[string]struct{ profile string }{
			"dump":            {profile: "dump"},
			"precedence":      {profile: "dump"},
			"config_relative": {profile: "dump"},
			"completion":      {profile: "dump"},
			"web":             {profile: "web"},
			"console":         {profile: "console"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				opts, m, cmd := scriptFlagCommand(t, tt.profile)
				confdir := opts.Str("confdir")
				path := filepath.Join(confdir, "addon.star")
				source := "def on_load(loader):\n    loader.add_option(\"script_flag_custom\", \"str\", \"loaded\", \"Script flag custom option.\")\n"
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				flag := cmd.Flags().Lookup("scripts")
				if flag == nil || flag.Shorthand != "s" {
					t.Fatal("registered script option did not expose both --scripts and -s")
				}
				if name == "completion" {
					var output bytes.Buffer
					if err := cmd.GenBashCompletion(&output); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(output.String(), "--scripts") {
						t.Fatal("static completion omits --scripts")
					}
					output.Reset()
					cmd.SetOut(&output)
					cmd.SetArgs([]string{"__complete", "--scr"})
					if err := cmd.ExecuteContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(output.String(), "--scripts") {
						t.Fatalf("dynamic completion omits --scripts: %q", output.String())
					}
					if opts.Has("script_flag_custom") || len(opts.Seq("scripts")) != 0 {
						t.Fatal("completion initialized an operator script")
					}
					return
				}
				args := []string{"--set", "script_flag_custom=custom", "-s", path}
				wantPaths := []string{path}
				switch name {
				case "dump":
					second := filepath.Join(confdir, "second.star")
					if err := os.WriteFile(second, []byte("label = \"second script\"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "--scripts", second)
					wantPaths = append(wantPaths, second)
				case "precedence":
					setPath, configPath := filepath.Join(confdir, "set.star"), filepath.Join(confdir, "config.star")
					for _, other := range []string{setPath, configPath} {
						if err := os.WriteFile(other, []byte("label = \"not selected\"\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					config := fmt.Sprintf("scripts:\n  - %q\n", configPath)
					if err := os.WriteFile(filepath.Join(confdir, "config.yaml"), []byte(config), 0o600); err != nil {
						t.Fatal(err)
					}
					args = append([]string{"--set", "scripts=" + setPath}, args...)
				case "config_relative":
					if err := os.WriteFile(filepath.Join(confdir, "config.yaml"), []byte("scripts:\n  - addon.star\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					args = []string{"--set", "script_flag_custom=custom"}
				}
				cmd.SetArgs(args)
				cmd.RunE = func(c *cobra.Command, _ []string) error { return Apply(t.Context(), c, opts, m.Do) }
				if err := cmd.ExecuteContext(t.Context()); err != nil {
					t.Fatalf("args=%q: %v", args, err)
				}
				if diff := gocmp.Diff(wantPaths, opts.Seq("scripts")); diff != "" {
					t.Fatalf("selected scripts (-want +got):\n%s", diff)
				}
				if got := opts.Str("script_flag_custom"); got != "custom" {
					t.Fatalf("custom option was not registered and applied synchronously: %q", got)
				}
				for _, path := range wantPaths {
					if m.Addons.Get("script:"+path) == nil {
						t.Fatalf("script %q was not registered", path)
					}
				}
			})
		}
	})
}

func scriptFlagCommand(t *testing.T, profile string) (*options.Manager, *master.Master, *cobra.Command) {
	t.Helper()
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir(), "server": false}); err != nil {
		t.Fatal(err)
	}
	var base *master.Master
	var closeMaster func(context.Context) error
	var cmd *cobra.Command
	switch profile {
	case "dump":
		m, err := dump.New(t.Context(), dump.Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard, WithTermlog: true, WithDumper: true})
		if err != nil {
			t.Fatal(err)
		}
		base, closeMaster, cmd = m.Master, m.Close, New(opts, "script-flags")
	case "web":
		m, err := web.New(t.Context(), web.Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard, WithTermlog: true})
		if err != nil {
			t.Fatal(err)
		}
		base, closeMaster, cmd = m.Master, m.Close, NewWeb(opts, "script-flags")
	case "console":
		m, err := console.New(t.Context(), console.Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard})
		if err != nil {
			t.Fatal(err)
		}
		base, closeMaster, cmd = m.Master, m.Close, NewConsole(opts, "script-flags")
	default:
		t.Fatalf("unknown frontend %q", profile)
	}
	t.Cleanup(func() {
		if err := closeMaster(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	return opts, base, cmd
}
