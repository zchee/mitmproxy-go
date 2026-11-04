// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestCommandPreservesExitCodesAndOutput covers successful and failed invocations.
func TestCommandPreservesExitCodesAndOutput(t *testing.T) {
	binary := verifyReader(t)
	tests := map[string]struct {
		args   []string
		code   int
		prefix string
	}{
		"valid tag":       {args: []string{"tag", "v1.2.3"}, prefix: "v1.2.3\n"},
		"missing command": {code: 1, prefix: "usage: releasecheck "},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			output, err := exec.CommandContext(t.Context(), binary, test.args...).CombinedOutput()
			code := 0
			if err != nil {
				exit, ok := errors.AsType[*exec.ExitError](err)
				if !ok {
					t.Fatalf("run releasecheck: %v", err)
				}
				code = exit.ExitCode()
			}
			if code != test.code || !strings.HasPrefix(string(output), test.prefix) {
				t.Fatalf("exit=%d output=%q; want exit=%d prefix=%q", code, output, test.code, test.prefix)
			}
		})
	}
}
