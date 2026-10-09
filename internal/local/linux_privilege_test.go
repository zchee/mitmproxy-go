// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/addons/errorcheck"
	"github.com/zchee/mitmproxy-go/master"
)

func TestLinuxElevationFailureStartupLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	tests := map[string]struct{}{"sudo denial remains a failing startup": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			command, stdout, cause := startLinuxRedirector(t.Context(), "unused-redirector", dir)
			if command != nil || stdout != nil || cause == nil {
				t.Fatalf("sudo probe = %v, %v, %v", command, stdout, cause)
			}
			var denied *exec.ExitError
			if !errors.As(cause, &denied) || denied.ExitCode() != 1 {
				t.Fatalf("wrapped sudo exit = %v", cause)
			}
			var stderr bytes.Buffer
			checker := errorcheck.New(errorcheck.Config{Stderr: &stderr, RepeatErrorsOnStderr: true})
			slog.New(checker.LogHandler()).ErrorContext(t.Context(), cause.Error())
			classified := checker.ShutdownIfErrored(t.Context())
			exit, ok := errors.AsType[*master.ExitError](classified)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("errorcheck startup exit = %v", classified)
			}
			if !strings.Contains(stderr.String(), "Failed to elevate privileges") {
				t.Fatalf("startup log lacks upstream privilege message: %q", stderr.String())
			}
		})
	}
}
