// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestMitmwebCommand(t *testing.T) {
	tests := map[string]struct {
		args   []string
		want   string
		prefix string
		status int
	}{
		"version":        {args: []string{"--version"}, want: "Mitmproxy-go:", prefix: "Mitmproxy-go:"},
		"help":           {args: []string{"--help"}, want: "--web-port"},
		"options":        {args: []string{"--options"}, want: "web_theme", prefix: "\n# "},
		"commands":       {args: []string{"--commands"}, want: "view.flows", prefix: "browser.start "},
		"completion":     {args: []string{"completion", "bash"}, want: "__start_mitmweb", prefix: "# bash completion V2 for mitmweb"},
		"complete_flags": {args: []string{"__complete", "--web-"}, want: "--web-port", prefix: "--web-"},
		"dump_flag":      {args: []string{"--flow-detail", "1"}, status: 1},
		"positional":     {args: []string{"~u", "example"}, status: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(t.Context(), tt.args, io.NopCloser(strings.NewReader("")), &stdout, &stderr)
			if got != tt.status {
				t.Fatalf("exit=%d want=%d stderr=%s", got, tt.status, stderr.String())
			}
			if tt.prefix != "" && !strings.HasPrefix(stdout.String(), tt.prefix) {
				t.Fatalf("stdout has diagnostics before machine-readable output: want prefix %q", tt.prefix)
			}
			if tt.want != "" && !strings.Contains(stdout.String(), tt.want) {
				t.Fatalf("missing %q in output: %s", tt.want, stdout.String())
			}
		})
	}
}
