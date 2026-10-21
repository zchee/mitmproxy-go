// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build unix

package acceptance_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func checkArtifactRootOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify directory ownership")
	}
	if uint64(stat.Uid) != uint64(os.Getuid()) { //nolint:gosec // Unix caller uid is nonnegative.
		return fmt.Errorf("directory must be owned by caller uid %d (owner uid %d)", os.Getuid(), stat.Uid)
	}
	return nil
}

func TestArtifactRoot(t *testing.T) {
	tests := map[string]struct {
		setup   func(*testing.T) string
		wantErr string
	}{
		"relative": {
			setup:   func(*testing.T) string { return "artifacts" },
			wantErr: "MITMPROXY_TEST_CONSOLE_ARTIFACTS must be an absolute path",
		},
		"nonexistent": {
			setup:   func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			wantErr: "resolve console artifact root",
		},
		"file": {
			setup: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "file")
				requireNoError(t, os.WriteFile(path, nil, 0o600))
				return path
			},
			wantErr: "must be an existing directory",
		},
		"absolute": {setup: func(t *testing.T) string { return t.TempDir() }},
		"group writable": {
			setup: func(t *testing.T) string {
				path := t.TempDir()
				requireNoError(t, os.Chmod(path, 0o720))
				return path
			},
			wantErr: "must not be group- or other-writable",
		},
		"other writable": {
			setup: func(t *testing.T) string {
				path := t.TempDir()
				requireNoError(t, os.Chmod(path, 0o702))
				return path
			},
			wantErr: "must not be group- or other-writable",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root := test.setup(t)
			got, err := resolveArtifactRoot(root)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("resolveArtifactRoot(%q) = %q, %v; want error containing %q", root, got, err, test.wantErr)
				}
				return
			}
			requireNoError(t, err)
			want, err := filepath.EvalSymlinks(root)
			requireNoError(t, err)
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatalf("artifact root (-want +got):\n%s", diff)
			}
			t.Setenv("MITMPROXY_TEST_CONSOLE_ARTIFACTS", root)
			out := consoleArtifactDir(t, "owned-")
			if diff := gocmp.Diff(want, filepath.Dir(out)); diff != "" {
				t.Fatalf("artifact parent (-want +got):\n%s", diff)
			}
		})
	}
}

func TestArtifactRootFallback(t *testing.T) {
	t.Setenv("MITMPROXY_TEST_CONSOLE_ARTIFACTS", "")
	out := consoleArtifactDir(t, "fallback-")
	canonical, err := filepath.EvalSymlinks(out)
	requireNoError(t, err)
	if diff := gocmp.Diff(canonical, out); diff != "" {
		t.Fatalf("fallback path is not canonical (-want +got):\n%s", diff)
	}
}
