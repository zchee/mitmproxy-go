// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestScriptCLI(t *testing.T) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("built race binary sha256=%x", sha256.Sum256(data))
	t.Run("cli", func(t *testing.T) {
		tests := map[string]struct{}{
			"load": {}, "custom_options": {}, "command_listing": {}, "reload": {}, "lifecycle_error": {},
		}
		for name := range tests {
			t.Run(name, func(t *testing.T) { scriptCLICase(t, binaryPath, name) })
		}
	})
}

func scriptCLICase(t *testing.T, binary, name string) {
	t.Helper()
	ready := make(chan struct{})
	events := make(chan string, 64)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events <- r.URL.Path
		if r.URL.Path == "/ready" {
			close(ready)
		}
		if _, err := io.WriteString(w, "origin body"); err != nil {
			t.Errorf("local origin response: %v", err)
		}
	}))
	defer origin.Close()
	confdir := t.TempDir()
	path := filepath.Join(confdir, "addon.star")
	prefix := fmt.Sprintf("ctx.http_get(%q)\ndef example():\n    ctx.log(\"CLI command invoked\")\ndef on_load(loader):\n    loader.add_option(\"cli_custom\", \"str\", \"default\", \"CLI custom option.\")\n    loader.add_command(\"cli.example\", example)\n    ctx.http_get(%q)\n", origin.URL+"/init", origin.URL+"/load")
	source := prefix + fmt.Sprintf("def running():\n    result = ctx.http_get(%q)\n    if result.content != b\"origin body\":\n        fail(\"unexpected local origin body\")\n    ctx.master.shutdown()\ndef done():\n    ctx.http_get(%q)\n", origin.URL+"/running", origin.URL+"/done")
	switch name {
	case "custom_options":
		source = prefix + fmt.Sprintf("def configure(updated):\n    if \"cli_custom\" in updated:\n        ctx.http_get(%q + ctx.options.cli_custom)\ndef running():\n    fail(\"metadata started the lifecycle\")\n", origin.URL+"/value/")
	case "command_listing":
		source = prefix + "def running():\n    fail(\"metadata started the lifecycle\")\n"
	case "reload":
		source = prefix + fmt.Sprintf("def running():\n    ctx.http_get(%q)\ndef done():\n    ctx.http_get(%q)\n", origin.URL+"/ready", origin.URL+"/retired")
	case "lifecycle_error":
		source = prefix + fmt.Sprintf("def running():\n    ctx.http_get(%q)\n    fail(\"CLI lifecycle failure\")\ndef done():\n    ctx.http_get(%q)\n", origin.URL+"/running", origin.URL+"/done")
	}
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--set", "confdir=" + confdir, "-n", "-s", path}
	switch name {
	case "custom_options":
		args = append(args, "--set", "cli_custom=chosen", "--options")
	case "command_listing":
		args = append(args, "--commands")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+confdir, "USERPROFILE="+confdir)
	cmd.WaitDelay = 2 * time.Second
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() {
		joined <- cmd.Wait()
		close(joined)
	}()
	defer func() {
		cancel()
		<-joined
		if t.Failed() {
			var remaining []string
			for len(events) != 0 {
				remaining = append(remaining, <-events)
			}
			t.Logf("joined child output:\n%s\norigin events: %q", output.String(), remaining)
		}
	}()
	if name == "reload" {
		select {
		case <-ready:
		case err := <-joined:
			t.Fatalf("process exited before reload synchronization: %v\n%s", err, output.String())
		case <-ctx.Done():
			t.Fatal("script running hook never reached the local origin")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		updated := fmt.Sprintf("ctx.http_get(%q)\ndef running():\n    ctx.http_get(%q)\n    ctx.master.shutdown()\ndef done():\n    ctx.http_get(%q)\n", origin.URL+"/reloaded", origin.URL+"/reloaded-running", origin.URL+"/done")
		next := filepath.Join(confdir, "next.star")
		if err := os.WriteFile(next, []byte(updated), 0o600); err != nil {
			t.Fatal(err)
		}
		newer := info.ModTime().Add(time.Second)
		if err := os.Chtimes(next, newer, newer); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(next, path); err != nil {
			t.Fatal(err)
		}
		replacement, err := os.Stat(path)
		if err != nil || !replacement.ModTime().After(info.ModTime()) {
			t.Fatalf("replacement mtime is not strictly newer: %v", err)
		}
	}
	var runErr error
	select {
	case runErr = <-joined:
	case <-ctx.Done():
		t.Fatal("script process did not exit and join before its deadline")
	}
	if name == "lifecycle_error" {
		exit, ok := errors.AsType[*exec.ExitError](runErr)
		if !ok || exit.ExitCode() != 1 || !strings.Contains(output.String(), "CLI lifecycle failure") || !strings.Contains(output.String(), "Addon error:") {
			t.Fatalf("lifecycle error did not fail the real process cleanly: %v\n%s", runErr, output.String())
		}
	} else if runErr != nil {
		t.Fatalf("real script process: %v\n%s", runErr, output.String())
	}
	if strings.Contains(output.String(), "DATA RACE") || strings.Contains(output.String(), "panic:") {
		t.Fatalf("script process crashed or raced:\n%s", output.String())
	}
	var observed []string
	for len(events) != 0 {
		observed = append(observed, <-events)
	}
	switch name {
	case "load", "lifecycle_error":
		if diff := gocmp.Diff([]string{"/init", "/load", "/running", "/done"}, observed); diff != "" {
			t.Fatalf("lifecycle effects (-want +got):\n%s", diff)
		}
	case "custom_options":
		for _, marker := range []string{"cli_custom: default", "CLI custom option.", "script_max_steps:", "scripts:"} {
			if !strings.Contains(output.String(), marker) {
				t.Fatalf("custom option metadata omits %q:\n%s", marker, output.String())
			}
		}
		if !slices.Contains(observed, "/value/chosen") || slices.Contains(observed, "/running") {
			t.Fatalf("deferred custom option or early exit failed: %q", observed)
		}
	case "command_listing":
		for _, marker := range []string{"cli.example", "script.run flows path"} {
			if !strings.Contains(output.String(), marker) {
				t.Fatalf("command metadata omits %q:\n%s", marker, output.String())
			}
		}
		if diff := gocmp.Diff([]string{"/init", "/load"}, observed); diff != "" {
			t.Fatalf("metadata lifecycle effects (-want +got):\n%s", diff)
		}
	case "reload":
		if diff := gocmp.Diff([]string{"/init", "/load", "/ready", "/retired", "/reloaded", "/reloaded-running", "/done"}, observed); diff != "" {
			t.Fatalf("reload lifecycle effects (-want +got):\n%s", diff)
		}
	}
}
