// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/releasecheck/releasetest"
)

var reader struct {
	sync.Mutex
	dir    string
	binary string
}

func TestMain(m *testing.M) {
	code := m.Run()
	releasetest.Cleanup()
	if reader.dir != "" {
		_ = os.RemoveAll(reader.dir)
	}
	os.Exit(code)
}

func verifyReader(t *testing.T) string {
	t.Helper()
	reader.Lock()
	defer reader.Unlock()
	if reader.binary != "" {
		return reader.binary
	}
	dir, err := os.MkdirTemp("", "releasecheck-reader-test-*")
	if err != nil {
		t.Fatal(err)
	}
	reader.dir = dir
	binary := filepath.Join(dir, "releasecheck")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build reader: %v\n%s", err, output)
	}
	reader.binary = binary
	return binary
}

func fixtureDirectory(t *testing.T, family *releasetest.Family) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range family.Files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func familyDigests(t *testing.T, dir string) map[string][sha256.Size]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	digests := make(map[string][sha256.Size]byte)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		digests[entry.Name()] = sha256.Sum256(data)
	}
	return digests
}

func TestVerifySource(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"explicit_source_root": {func(t *testing.T) {
				family := releasetest.Load(t, false)
				dir := fixtureDirectory(t, family)
				before := familyDigests(t, dir)
				cmd := exec.CommandContext(t.Context(), verifyReader(t), "verify", dir, releasetest.Tag, "--source-root", family.Root, "--go-version", "go1.27.3")
				cmd.Dir = t.TempDir()
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("explicit trusted root: %v\n%s", err, output)
				}
				if diff := gocmp.Diff(before, familyDigests(t, dir)); diff != "" {
					t.Fatalf("verification changed family (-before +after):\n%s", diff)
				}
			}},
			"default_source_root": {func(t *testing.T) {
				family := releasetest.Load(t, false)
				dir := fixtureDirectory(t, family)
				cmd := exec.CommandContext(t.Context(), verifyReader(t), "verify", dir, releasetest.Tag, "--go-version", "go1.27.3")
				cmd.Dir = family.Root
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("default trusted root: %v\n%s", err, output)
				}
			}},
			"wrong_source_refused": {verifyWrongSource},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func verifyWrongSource(t *testing.T) {
	family := releasetest.Load(t, false)
	dir := fixtureDirectory(t, family)
	binary := verifyReader(t)
	tests := map[string]struct {
		args     []string
		contains string
	}{
		"missing expected compiler":               {[]string{}, "requires --go-version"},
		"missing go prefix":                       {[]string{"--go-version", "1.27.3"}, "requires --go-version"},
		"space in expected compiler":              {[]string{"--go-version", "go1.27.3 extra"}, "requires --go-version"},
		"unicode whitespace in expected compiler": {[]string{"--go-version", "go1.27.3 "}, "requires --go-version"},
		"wrong expected compiler":                 {[]string{"--go-version", "go1.26.0"}, "source provenance mismatch"},
		"relative trusted root":                   {[]string{"--go-version", "go1.27.3", "--source-root", "."}, "must be absolute"},
		"unknown option":                          {[]string{"--go-version", "go1.27.3", "--unexpected"}, "flag provided but not defined"},
		"extra positional argument":               {[]string{"--go-version", "go1.27.3", "extra"}, "requires --go-version"},
	}
	for name, tt := range tests {
		args := append([]string{"verify", dir, releasetest.Tag}, tt.args...)
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Dir = family.Root
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), tt.contains) {
			t.Errorf("%s: expected %q rejection, got err=%v output=%s", name, tt.contains, err, output)
		}
	}
	wrongRoot := filepath.Join(t.TempDir(), "source")
	clone := exec.CommandContext(t.Context(), "git", "clone", "--quiet", "--local", "--no-hardlinks", family.Root, wrongRoot)
	if output, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("clone owned source: %v\n%s", err, output)
	}
	if err := os.WriteFile(filepath.Join(wrongRoot, "LICENSE"), []byte("different source license\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, "verify", dir, releasetest.Tag, "--source-root", wrongRoot, "--go-version", "go1.27.3")
		cmd.Dir = family.Root
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), want) {
			t.Fatalf("wrong trusted source: expected %q, err=%v output=%s", want, err, output)
		}
	}
	check("source checkout must be clean")
	for _, args := range [][]string{
		{"-C", wrongRoot, "add", "LICENSE"},
		{"-C", wrongRoot, "-c", "user.name=Release fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture: distinguish trusted sources"},
	} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("change owned source: %v\n%s", err, output)
		}
	}
	check("source provenance mismatch")
	metadata := filepath.Join(dir, "mitmproxy-go_"+releasetest.Tag+"_linux_amd64.provenance.json")
	if err := os.WriteFile(metadata, []byte(strings.Repeat(" ", 1<<20+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), binary, "verify", dir, releasetest.Tag, "--source-root", family.Root, "--go-version", "go1.27.3")
	cmd.Dir = family.Root
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "provenance exceeds size bound") {
		t.Fatalf("oversized metadata accepted or wrong rejection: %v\n%s", err, output)
	}
}
