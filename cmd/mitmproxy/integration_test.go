//go:build integration

// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/tools/cmdline"
	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMitmproxyCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "mitmproxy")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real console executable: %v\n%s", err, output)
	}
	t.Run("cli", func(t *testing.T) {
		tests := map[string]struct{}{"metadata": {}, "profiles_precedence": {}, "completion": {}, "non_tty": {}, "startup_errors": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				home := t.TempDir()
				run := func(args ...string) (string, string, error) {
					ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // This is the freshly built, test-owned console executable.
					cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
					var stdout, stderr bytes.Buffer
					cmd.Stdout, cmd.Stderr = &stdout, &stderr
					err := cmd.Run()
					return stdout.String(), stderr.String(), err
				}
				directory := t.TempDir()
				common := []string{"--set", "confdir=" + directory}
				switch name {
				case "metadata":
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := listener.Close(); err != nil {
							t.Error(err)
						}
					}()
					tests := map[string]struct {
						args []string
						want string
					}{
						"help":     {[]string{"--help"}, "--console-layout"},
						"version":  {[]string{"--version"}, "Mitmproxy-go:"},
						"options":  {[]string{"--options"}, "console_layout"},
						"commands": {[]string{"--commands"}, "console.keymap.load"},
					}
					for caseName, test := range tests {
						args := append([]string{}, common...)
						args = append(args, "--set", fmt.Sprintf("mode=regular@%s", listener.Addr()))
						args = append(args, test.args...)
						stdout, stderr, err := run(args...)
						if err != nil || !strings.Contains(stdout, test.want) || stderr != "" {
							t.Fatalf("%s early exit: %v\nstdout=%s\nstderr=%s", caseName, err, stdout, stderr)
						}
						if caseName == "commands" {
							count := 0
							for line := range strings.SplitSeq(stdout, "\n") {
								if strings.HasPrefix(line, "console.") {
									count++
								}
							}
							if count != 49 {
								t.Fatalf("console namespace count=%d, want 49", count)
							}
						}
					}
					// Option application may initialize TLS material in the explicit confdir,
					// but metadata must not use the default directory beneath HOME.
					entries, err := os.ReadDir(home)
					if err != nil {
						t.Fatal(err)
					}
					if len(entries) != 0 {
						t.Fatalf("metadata touched the isolated home outside confdir: %v", entries)
					}
				case "profiles_precedence":
					config := []byte("console_layout: horizontal\nconsole_mouse: false\n")
					if err := os.WriteFile(filepath.Join(directory, "config.yaml"), config, 0o600); err != nil {
						t.Fatal(err)
					}
					args := append([]string{}, common...)
					args = append(args, "--set", "console_layout=single", "--console-layout", "vertical", "--no-console-layout-headers", "--options")
					stdout, stderr, err := run(args...)
					if err != nil {
						t.Fatalf("profile precedence: %v stderr=%s", err, stderr)
					}
					for _, want := range []string{"console_layout: single", "console_layout_headers: true", "console_mouse: true"} {
						if !strings.Contains(stdout, want) {
							t.Fatalf("missing default option %q in %s", want, stdout)
						}
					}
					opts := options.New()
					m, err := console.New(t.Context(), console.Config{Options: opts})
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
							t.Error(err)
						}
					}()
					cmd := cmdline.NewConsole(opts, "test")
					if err := cmd.ParseFlags(args); err != nil {
						t.Fatal(err)
					}
					if err := cmdline.Apply(t.Context(), cmd, opts, m.Do); err != nil {
						t.Fatal(err)
					}
					if opts.Str("console_layout") != "vertical" || opts.Bool("console_layout_headers") || opts.Bool("console_mouse") {
						t.Fatalf("current options lost precedence: layout=%q headers=%t mouse=%t", opts.Str("console_layout"), opts.Bool("console_layout_headers"), opts.Bool("console_mouse"))
					}
					for _, absent := range []string{"termlog_verbosity:", "flow_detail:", "web_port:"} {
						if strings.Contains(stdout, absent) {
							t.Fatalf("unregistered profile option leaked: %s", absent)
						}
					}
				case "completion":
					tests := map[string]struct{ marker string }{
						"bash":       {"__start_mitmproxy"},
						"zsh":        {"compdef _mitmproxy mitmproxy"},
						"fish":       {"complete -c mitmproxy"},
						"powershell": {"Register-ArgumentCompleter -CommandName 'mitmproxy'"},
					}
					for shell, test := range tests {
						stdout, stderr, err := run("completion", shell)
						if err != nil || stderr != "" || !strings.Contains(stdout, test.marker) || !strings.Contains(stdout, "__complete") {
							t.Fatalf("%s completion: %v\nstdout=%s\nstderr=%s", shell, err, stdout, stderr)
						}
					}
					stdout, stderr, err := run("__complete", "--console-l")
					if err != nil || !strings.Contains(stdout, "--console-layout") {
						t.Fatalf("flag completion: %v stdout=%s stderr=%s", err, stdout, stderr)
					}
				case "non_tty":
					args := append([]string{}, common...)
					args = append(args, "--no-server")
					_, stderr, err := run(args...)
					if err == nil || !strings.Contains(stderr, "console interface requires a tty") || !strings.Contains(stderr, "interactive shell environment") {
						t.Fatalf("non-TTY: %v stderr=%s", err, stderr)
					}
				case "startup_errors":
					tests := map[string]struct{ args []string }{
						"bad layout":        {[]string{"--console-layout", "unknown"}},
						"bad option":        {[]string{"--set", "console_option_does_not_exist=true"}},
						"bad mode":          {[]string{"--set", "mode=not-a-proxy-mode"}},
						"dump flag":         {[]string{"--flow-detail", "4"}},
						"positional filter": {[]string{"~u", "example.com"}},
					}
					for caseName, test := range tests {
						args := append(append([]string{}, common...), test.args...)
						_, stderr, err := run(args...)
						if err == nil || stderr == "" || strings.Contains(stderr, "panic:") {
							t.Fatalf("%s: %v stderr=%s", caseName, err, stderr)
						}
					}
				}
			})
		}
	})
}
