// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package processinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestActiveExecutables(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	processes, err := ActiveExecutables()
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, len(processes))
	found := false
	for _, process := range processes {
		if process.Executable == "" || process.DisplayName == "" {
			t.Fatalf("empty executable or display name: %+v", process)
		}
		if _, duplicate := seen[process.Executable]; duplicate {
			t.Fatalf("duplicate executable: %q", process.Executable)
		}
		seen[process.Executable] = struct{}{}
		normalized, err := filepath.EvalSymlinks(process.Executable)
		if err == nil && normalized == executable {
			found = true
		}
	}
	if !found {
		t.Fatalf("current executable %q missing from %d grouped executables", executable, len(processes))
	}
}
