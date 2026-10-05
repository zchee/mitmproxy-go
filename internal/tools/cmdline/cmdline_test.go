// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package cmdline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"

	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// Upstream test_cmdline.py: test_common and test_mitmdump are covered below.
// test_mitmproxy and test_mitmweb exercise frontends not built by this package.
// Upstream test_main.py: test_mitmdump and test_mitmweb require the executable
// assembly; test_options_includes_addon_options requires script loading, and
// test_options_without_scripts requires the executable's option-dump handler.
func TestParse(t *testing.T) {
	tests := map[string]struct {
		args []string
		want map[string]any
		err  bool
	}{
		"success: no arguments":                            {want: map[string]any{"server": true, "listen_port": (*int)(nil)}},
		"success: short boolean inverts default":           {args: []string{"-n", "-k"}, want: map[string]any{"server": false, "ssl_insecure": true}},
		"success: repeated scalar keeps last":              {args: []string{"-p", "12", "--listen-port", "010"}, want: map[string]any{"listen_port": new(10)}},
		"success: python integer spelling":                 {args: []string{"-p", " +1_234 "}, want: map[string]any{"listen_port": new(1234)}},
		"success: repeated sequences preserve punctuation": {args: []string{"--ignore-hosts", "a,b", "--ignore-hosts", "\"c\""}, want: map[string]any{"ignore_hosts": []string{"a,b", "\"c\""}}},
		"success: set sequences preserve punctuation":      {args: []string{"--set", "ignore_hosts=a,b", "--set", "ignore_hosts=\"c\""}, want: map[string]any{"ignore_hosts": []string{"a,b", "\"c\""}}},
		"success: explicit flag wins over set":             {args: []string{"-p", "9", "--set", "listen_port=1"}, want: map[string]any{"listen_port": new(9)}},
		"success: boolean set toggle":                      {args: []string{"--set", "server=toggle"}, want: map[string]any{"server": false}},
		"success: positional filters consume remainder":    {args: []string{"~u", "example", "--no-server"}, want: map[string]any{"server": true, "save_stream_filter": new("~u example --no-server"), "readfile_filter": new("~u example --no-server"), "dumper_filter": new("~u example --no-server")}},
		"success: dash dash separates filter":              {args: []string{"--", "--no-server"}, want: map[string]any{"server": true, "dumper_filter": new("--no-server")}},
		"success: quiet overrides detail":                  {args: []string{"-q", "--flow-detail", "4"}, want: map[string]any{"termlog_verbosity": "error", "flow_detail": 0}},
		"success: verbose overrides quiet and detail":      {args: []string{"-v", "-q", "--flow-detail", "4"}, want: map[string]any{"termlog_verbosity": "debug", "flow_detail": 2}},
		"success: options silences startup":                {args: []string{"--options"}, want: map[string]any{"termlog_verbosity": "error", "flow_detail": 0}},
		"success: commands silences startup":               {args: []string{"--commands"}, want: map[string]any{"termlog_verbosity": "error", "flow_detail": 0}},
		"success: repeated same boolean":                   {args: []string{"--server", "--server"}, want: map[string]any{"server": true}},
		"error: conflicting booleans":                      {args: []string{"--server", "--no-server"}, err: true},
		"error: reverse conflicting booleans":              {args: []string{"-n", "--server"}, err: true},
		"error: unregistered addon":                        {args: []string{"--scripts", "file.py"}, err: true},
		"error: unknown option":                            {args: []string{"--nonesuch"}, err: true},
		"error: integer":                                   {args: []string{"-p", "abc"}, err: true},
		"error: empty integer":                             {args: []string{"--listen-port="}, err: true},
		"error: hexadecimal integer":                       {args: []string{"-p", "0x12"}, err: true},
		"error: missing argument":                          {args: []string{"-p"}, err: true},
		"error: invalid choice":                            {args: []string{"--server-replay-extra", "invalid"}, err: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := testOptions(t)
			cmd := testCommand(t, opts)
			cmd.SetArgs(tt.args)
			err := cmd.ExecuteContext(t.Context())
			if (err != nil) != tt.err {
				t.Fatalf("Execute(%q) error = %v, want error %v", tt.args, err, tt.err)
			}
			for key, want := range tt.want {
				if diff := cmp.Diff(want, opts.Current(key)); diff != "" {
					t.Errorf("option %s (-want +got):\n%s", key, diff)
				}
			}
		})
	}
}

func testOptions(t *testing.T) *options.Manager {
	t.Helper()
	opts := options.New()
	for _, entry := range []struct {
		name string
		typ  options.Type
		def  any
	}{
		{"flow_detail", options.TypeInt, 1},
		{"termlog_verbosity", options.TypeStr, "info"},
		{"save_stream_filter", options.TypeOptStr, (*string)(nil)},
		{"readfile_filter", options.TypeOptStr, (*string)(nil)},
		{"dumper_filter", options.TypeOptStr, (*string)(nil)},
	} {
		if err := opts.Add(t.Context(), entry.name, entry.typ, entry.def, "Test option."); err != nil {
			t.Fatal(err)
		}
	}
	if err := opts.Add(t.Context(), "server_replay_extra", options.TypeStr, "forward", "Unmatched replay requests.", options.WithChoices("forward", "kill")); err != nil {
		t.Fatal(err)
	}
	if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	return opts
}

func testCommand(t *testing.T, opts *options.Manager) *cobra.Command {
	t.Helper()
	m := master.New(master.Config{Options: opts})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	cmd := New(opts, "test")
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return Apply(cmd.Context(), cmd, opts, m.Do)
	}
	return cmd
}

func TestPrecedence(t *testing.T) {
	tests := map[string]struct {
		yaml, yml bool
		flag      bool
		want      int
	}{
		"success: passed flag":   {true, true, true, 4},
		"success: second config": {true, true, false, 3},
		"success: first config":  {true, false, false, 2},
		"success: set":           {false, false, false, 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := testOptions(t)
			dir := t.TempDir()
			for file, enabled := range map[string]bool{"config.yaml": tt.yaml, "config.yml": tt.yml} {
				if enabled {
					value := 2
					if file == "config.yml" {
						value = 3
					}
					if err := os.WriteFile(filepath.Join(dir, file), fmt.Appendf(nil, "listen_port: %d\n", value), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			cmd := testCommand(t, opts)
			args := []string{"--set", "confdir=" + dir, "--set", "listen_port=1"}
			if tt.flag {
				args = append(args, "-p", "4")
			}
			cmd.SetArgs(args)
			if err := cmd.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(new(tt.want), opts.OptInt("listen_port")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	cmd := New(options.New(), "1.2.3")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--version"})
	cmd.RunE = func(*cobra.Command, []string) error { t.Fatal("version must not start the proxy"); return nil }
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("Mitmproxy-go: 1.2.3\nGo: %s\nPlatform: %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if diff := cmp.Diff(want, out.String()); diff != "" {
		t.Fatal(diff)
	}
}

func TestApplyDispatch(t *testing.T) {
	opts := testOptions(t)
	cmd := New(opts, "test")
	if err := cmd.ParseFlags([]string{"-n"}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("dispatch unavailable")
	if err := Apply(t.Context(), cmd, opts, func(context.Context, func(context.Context) error) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want dispatch error", err)
	}
	if !opts.Bool("server") {
		t.Fatal("option changed outside the dispatch callback")
	}
}

func TestHelp(t *testing.T) {
	cmd := New(options.New(), "test")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"--listen-port PORT", "--listen-host HOST", "--certs SPEC", "--mode MODE", "May be passed multiple times.", "--no-server", "--set option[=value]"} {
		if !strings.Contains(out.String(), text) {
			t.Errorf("help missing %q:\n%s", text, out.String())
		}
	}
}
