// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/releasecheck/releasetest"
)

func TestReleaseToolchainPolicy(t *testing.T) {
	policy, err := filepath.Abs("../../../../hack/release-policy.sh")
	if err != nil {
		t.Fatal(err)
	}
	family := releasetest.Load(t, false)
	version := strings.TrimPrefix(family.PlainGoVersion, "go")
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			module     string
			command    string
			expected   string
			experiment string
			untrusted  bool
			gitFailure bool
			wantError  string
		}{
			"go_mod_plain":                 {command: "verify-toolchain", expected: family.PlainGoVersion},
			"missing_version":              {module: "module example.invalid/release\n", command: "go-version", wantError: "go.mod has no go directive"},
			"invalid_version":              {module: "module example.invalid/release\n\ngo 1.27.3-X:simd\n", command: "go-version", wantError: "invalid plain Go version"},
			"experiment_rejected":          {command: "verify-toolchain", expected: family.PlainGoVersion, experiment: "simd", wantError: "release Go experiments must be empty"},
			"wrong_expected_rejected":      {command: "verify-toolchain", expected: "go1.26.0", wantError: "expected Go version differs from trusted go.mod"},
			"trusted_source_only":          {command: "go-version", untrusted: true},
			"toolchain_directive_rejected": {module: "module example.invalid/release\n\ngo " + version + "\ntoolchain " + family.PlainGoVersion + "\n", command: "go-version", wantError: "toolchain directives are not allowed"},
			"git_query_failure_rejected":   {command: "go-version", gitFailure: true, wantError: "cannot read source status"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "source")
				clone := exec.CommandContext(t.Context(), "git", "clone", "--quiet", "--local", "--no-hardlinks", family.Root, root)
				if output, err := clone.CombinedOutput(); err != nil {
					t.Fatalf("clone owned source: %v\n%s", err, output)
				}
				if tt.module != "" {
					if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(tt.module), 0o600); err != nil {
						t.Fatal(err)
					}
					for _, args := range [][]string{
						{"-C", root, "add", "go.mod"},
						{"-C", root, "-c", "user.name=Release fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture: exercise compiler policy"},
					} {
						if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
							t.Fatalf("commit owned source: %v\n%s", err, output)
						}
					}
				}
				if tt.gitFailure {
					if err := os.WriteFile(filepath.Join(root, ".git", "index"), []byte("invalid index\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				dir := root
				if tt.untrusted {
					dir = t.TempDir()
					if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("go 1.26.0\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				run := func() ([]byte, error) {
					args := []string{policy, tt.command, root}
					if tt.expected != "" {
						args = append(args, tt.expected)
					}
					cmd := exec.CommandContext(t.Context(), "bash", args...)
					cmd.Dir = dir
					cmd.Env = slices.DeleteFunc(os.Environ(), func(value string) bool {
						key, _, _ := strings.Cut(value, "=")
						return slices.Contains([]string{"GOENV", "GOFLAGS", "GOWORK", "GOTOOLCHAIN", "GOEXPERIMENT"}, key)
					})
					cmd.Env = append(cmd.Env, "GOENV=off", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN="+family.PlainGoVersion, "GOEXPERIMENT="+tt.experiment)
					return cmd.CombinedOutput()
				}
				output, err := run()
				if tt.wantError != "" {
					if err == nil || !strings.Contains(string(output), tt.wantError) {
						t.Fatalf("expected %q rejection, got err=%v output=%s", tt.wantError, err, output)
					}
					if tt.gitFailure {
						if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[invalid\n"), 0o600); err != nil {
							t.Fatal(err)
						}
						if output, err := run(); err == nil || !strings.Contains(string(output), "cannot read source root") {
							t.Fatalf("source query failure accepted: err=%v output=%s", err, output)
						}
					}
					return
				}
				if err != nil {
					t.Fatalf("compiler policy: %v\n%s", err, output)
				}
				if diff := gocmp.Diff(version+"\n", string(output)); diff != "" {
					t.Fatalf("trusted compiler (-want +got):\n%s", diff)
				}
				if tt.untrusted {
					if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("go 1.26.0\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					if output, err := run(); err == nil || !strings.Contains(string(output), "source checkout must be clean") {
						t.Fatalf("dirty source accepted: err=%v output=%s", err, output)
					}
				}
			})
		}
	})
}
