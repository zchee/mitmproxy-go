// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package difftest runs Python code against the pinned upstream mitmproxy, so
// that tests can compare the port's behaviour with upstream's.
//
// Differential tests need uv and network access on their first run, so they
// run only in a binary built with the difftest build tag:
//
//	go test -tags difftest ./...
//
// Without the tag, or when uv is not installed, every helper skips the
// calling test.
package difftest

import (
	"bytes"
	"os/exec"
	"testing"
)

// PinnedCommit is the upstream mitmproxy commit that differential tests run
// against.
const PinnedCommit = "3368a0a06ae6195aad817a1ece1aaeb6fe0353a1"

// Requirement is the uv requirement that installs mitmproxy at PinnedCommit.
const Requirement = "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@" + PinnedCommit

// PythonVersion is the Python version uv runs the scripts with. Upstream
// supports 3.12 and later.
const PythonVersion = "3.13"

// Enabled reports whether the test binary was built with the difftest build
// tag.
const Enabled = enabled

// UV returns the path of the uv executable. It skips the test when the binary
// was built without the difftest build tag or when uv is not installed.
func UV(t testing.TB) string {
	t.Helper()

	if !Enabled {
		t.Skip("differential test: build with -tags difftest to run it")
	}
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Skipf("differential test: uv is not installed: %v", err)
	}
	return uv
}

// Python runs the Python source script with mitmproxy at PinnedCommit
// installed, feeds it stdin, and returns its standard output. It fails the
// test, showing the standard error, if the script exits with an error, and it
// skips the test as UV does.
func Python(t testing.TB, script string, stdin []byte) []byte {
	t.Helper()

	return run(t, stdin, "run", "--quiet", "--no-project", "--python", PythonVersion,
		"--with", Requirement, "python", "-c", script)
}

// Script runs the Python script file at path with args and returns its
// standard output. The script declares its own dependencies in an inline
// script metadata block (PEP 723), which should pin mitmproxy to Requirement.
// It fails and skips the test as Python does.
func Script(t testing.TB, path string, args ...string) []byte {
	t.Helper()

	return run(t, nil, append([]string{"run", "--quiet", "--python", PythonVersion, "--script", path}, args...)...)
}

// run runs uv with args, feeding it stdin, and returns its standard output.
func run(t testing.TB, stdin []byte, args ...string) []byte {
	t.Helper()

	// The arguments are the calling test's own script and file paths, not
	// external input; running uv with them is what this package is for.
	cmd := exec.CommandContext(t.Context(), UV(t), args...) //nolint:gosec // G204: arguments come from the calling test.
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("difftest: %s: %v\nstderr:\n%s", cmd, err, stderr.Bytes())
	}
	return out
}
