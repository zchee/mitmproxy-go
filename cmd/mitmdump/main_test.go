// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Upstream test/mitmproxy/tools/test_main.py maps onto this file as
// follows:
//
//	test_mitmweb                        -> not applicable: the web frontend
//	                                       is a different binary, not built
//	                                       yet.
//	test_mitmdump                       -> TestSignalShutdown and
//	                                       TestSignalBinary; the upstream
//	                                       case shuts the master down from
//	                                       an addon script, which needs the
//	                                       scripts option no ported addon
//	                                       registers.
//	test_options_includes_addon_options -> not applicable: addon scripts
//	                                       need the scripts option, which no
//	                                       ported addon registers.
//	test_options_without_scripts        -> TestOptionsListing
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/eventsequence"
	"github.com/zchee/mitmproxy-go/addons/dumper"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/options"
)

var binaryPath string

// TestMain builds the production binary separately: test-only imports must
// not supply layer factories that the real binary forgot to link.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mitmdump-binary-")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "mitmdump")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	cmd := exec.CommandContext(ctx, "go", "build", "-race", "-o", binaryPath, ".")
	output, err := cmd.CombinedOutput()
	cancel()
	if err != nil {
		stack := make([]byte, 1<<20)
		_, _ = fmt.Fprintf(os.Stderr, "build mitmdump: %v\n%s\n%s", err, output, stack[:runtime.Stack(stack, true)])
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	if err := os.RemoveAll(dir); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

// child runs the production mitmdump with isolated configuration.
func child(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	if !slices.ContainsFunc(args, func(arg string) bool { return strings.HasPrefix(arg, "confdir=") }) {
		args = append([]string{"--set", "confdir=" + t.TempDir()}, args...)
	}
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Cancel = func() error {
		stack := make([]byte, 1<<20)
		t.Logf("child hang detector fired; parent goroutines:\n%s", stack[:runtime.Stack(stack, true)])
		return cmd.Process.Kill()
	}
	return cmd
}

func goRun(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := child(t, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

// versionLines is the exact three-line --version output.
func versionLines() string {
	return fmt.Sprintf("Mitmproxy-go: %s\nGo: %s\nPlatform: %s/%s\n", version.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(t.Context(), []string{"--version"}, nil, &out, &errOut); code != 0 {
		t.Fatalf("exit status %d, stderr %q", code, errOut.String())
	}
	if diff := gocmp.Diff(versionLines(), out.String()); diff != "" {
		t.Fatalf("version output (-want +got):\n%s", diff)
	}
	if lines := strings.Count(out.String(), "\n"); lines != 3 {
		t.Fatalf("version output has %d lines, want 3", lines)
	}
}

// TestVersionBinary runs the real process, which must print the three
// lines on standard output and exit with status 0.
func TestVersionBinary(t *testing.T) {
	out, err := child(t, "--version").Output()
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	if diff := gocmp.Diff(versionLines(), string(out)); diff != "" {
		t.Fatalf("version output (-want +got):\n%s", diff)
	}
}

func TestOptionsListing(t *testing.T) {
	out, stderr, code := goRun(t, "--options")
	if code != 0 {
		t.Fatalf("exit status %d, stderr %q", code, stderr)
	}
	if !strings.Contains(out, "listen_port") {
		t.Error("the option listing does not name listen_port")
	}
	if strings.Contains(out, "custom_addon_option") {
		t.Error("the option listing names an addon-script option that cannot be registered")
	}
}

func TestCommandsListing(t *testing.T) {
	out, stderr, code := goRun(t, "--commands")
	if code != 0 {
		t.Fatalf("exit status %d, stderr %q", code, stderr)
	}
	for _, name := range []string{"flow.kill", "options.save", "save.file"} {
		if !strings.Contains(out, name) {
			t.Errorf("the command listing does not name %s", name)
		}
	}
}

// TestOptionsError checks upstream's error exit: the message is printed
// as "<argv0>: <error>" and the status is 1.
func TestOptionsError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(t.Context(), []string{"--set", "listen_port=not-a-port"}, nil, &out, &errOut); code != 1 {
		t.Fatalf("exit status %d, want 1", code)
	}
	if !strings.HasPrefix(errOut.String(), os.Args[0]+": ") {
		t.Fatalf("stderr %q does not start with %q", errOut.String(), os.Args[0]+": ")
	}
}

// render runs every flow of the file through a bare dumper at the given
// detail level and returns the text, the reference for what the binary
// must print for the same file and level.
func render(t *testing.T, path string, detail int) string {
	t.Helper()
	opts := options.New()
	var out bytes.Buffer
	d := dumper.New(opts, &out)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options().Update(ctx, map[string]any{"flow_detail": detail})
	})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	for f, err := range flowio.NewReader(file).All() {
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for hook := range eventsequence.Iterate(f) {
			if err := m.Hook(t.Context(), hook); err != nil {
				t.Fatalf("%s hook: %v", hook.Name(), err)
			}
		}
	}
	return out.String()
}

// TestPrecedence drives the option sources through the whole binary and
// observes the effective flow_detail in the dumper's output, with the
// expected resolution dedicated flag > config.yml > config.yaml > --set.
func TestPrecedence(t *testing.T) {
	fixture := testutil.FixturePath(t, "mitmproxy/flows/successful_log.mitm")
	tests := map[string]struct {
		yaml, yml string
		args      []string
		want      int
	}{
		"success: a passed flag wins over both configuration files": {
			yaml: "flow_detail: 2\n",
			yml:  "flow_detail: 3\n",
			args: []string{"--set", "flow_detail=1", "--flow-detail", "4"},
			want: 4,
		},
		"success: config.yml wins over config.yaml": {
			yaml: "flow_detail: 2\n",
			yml:  "flow_detail: 3\n",
			args: []string{"--set", "flow_detail=1"},
			want: 3,
		},
		"success: config.yaml wins over --set": {
			yaml: "flow_detail: 2\n",
			args: []string{"--set", "flow_detail=1"},
			want: 2,
		},
		"success: --set wins over the default": {
			args: []string{"--set", "flow_detail=0"},
			want: 0,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			confdir := t.TempDir()
			if tt.yaml != "" {
				if err := os.WriteFile(filepath.Join(confdir, "config.yaml"), []byte(tt.yaml), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.yml != "" {
				if err := os.WriteFile(filepath.Join(confdir, "config.yml"), []byte(tt.yml), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"-n", "-r", fixture, "--set", "confdir=" + confdir}
			args = append(args, tt.args...)
			out, stderr, code := goRun(t, args...)
			if code != 0 {
				t.Fatalf("exit status %d, stderr %q", code, stderr)
			}
			if diff := gocmp.Diff(render(t, fixture, tt.want), out); diff != "" {
				t.Fatalf("output is not the detail-%d rendering (-want +got):\n%s", tt.want, diff)
			}
		})
	}
}

func TestOccupiedListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := goRun(t, "--listen-host", "127.0.0.1", "-p", port)
	if code != 1 || stderr != "Error logged during startup, exiting...\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want startup failure and exit 1", code, stdout, stderr)
	}
}

// TestReadNoServerExits checks mitmdump -nr: the flows are printed and the
// process ends on its own with status 0 once reading finishes.
func TestReadNoServerExits(t *testing.T) {
	fixture := testutil.FixturePath(t, "mitmproxy/flows/successful_log.mitm")
	out, err := child(t, "-n", "-r", fixture).Output()
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	if diff := gocmp.Diff(render(t, fixture, 1), string(out)); diff != "" {
		t.Fatalf("output (-want +got):\n%s", diff)
	}
}
