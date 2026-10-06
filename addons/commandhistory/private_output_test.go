// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package commandhistory

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPrivateOutputPaths(t *testing.T) {
	tests := map[string]struct{ append, symlink, foreign bool }{
		"success: narrow existing file":       {},
		"error: symlink refused":              {symlink: true},
		"error: foreign owner refused":        {foreign: true},
		"success: append preserves content":   {append: true},
		"error: append symlink refused":       {append: true, symlink: true},
		"error: append foreign owner refused": {append: true, foreign: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			payload := "new\n"
			if runtime.GOOS == "windows" {
				payload = "new\r\n"
			}
			seed := "prior"
			path := filepath.Join(t.TempDir(), "output")
			target := path
			if test.symlink {
				target += "-target"
			}
			if err := os.WriteFile(target, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0o644)
			if test.foreign {
				if runtime.GOOS == "windows" {
					t.Skip("POSIX ownership is not available on Windows")
				}
				uid := 0
				if os.Geteuid() == 0 {
					uid = 1
				}
				if err := os.Chown(target, uid, -1); err != nil {
					t.Skipf("cannot create a foreign-owned file: %v", err)
				}
				mode = 0o666
			}
			if err := os.Chmod(target, mode); err != nil {
				t.Fatal(err)
			}
			if test.symlink {
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("cannot create symlink: %v", err)
				}
			}
			flags := os.O_TRUNC
			if test.append {
				flags = os.O_APPEND
			}
			err := writeHistory(path, "new\n", flags)
			refused := test.symlink || test.foreign
			if refused && err == nil {
				t.Error("unsafe output was not refused")
			}
			if !refused && err != nil {
				t.Fatal(err)
			}
			want := payload
			if refused {
				want = seed
			} else if test.append {
				want = seed + payload
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, string(got)); diff != "" {
				t.Errorf("output (-want +got):\n%s", diff)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" {
				wantMode := os.FileMode(0o600)
				if refused {
					wantMode = mode
				}
				if diff := cmp.Diff(wantMode, info.Mode().Perm()); diff != "" {
					t.Errorf("output permissions (-want +got):\n%s", diff)
				}
			}
		})
	}
}
