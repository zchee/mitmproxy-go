// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package privfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPrivateOutput(t *testing.T) {
	tests := map[string]struct{ append, existing, symlink, directory bool }{
		"success: create":               {},
		"success: overwrite and narrow": {existing: true},
		"success: append and narrow":    {append: true, existing: true},
		"success: append new":           {append: true},
		"error: overwrite symlink":      {existing: true, symlink: true},
		"error: append symlink":         {append: true, existing: true, symlink: true},
		"error: directory":              {directory: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "output")
			target := path
			if test.directory {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if test.symlink {
				target = path + "-target"
			}
			if test.existing {
				if err := os.WriteFile(target, []byte("prior"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(target, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if test.symlink {
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("cannot create symlink: %v", err)
				}
			}
			open := Create
			if test.append {
				open = Append
			}
			file, err := open(path)
			if test.symlink || test.directory {
				if err == nil {
					_ = file.Close()
					t.Fatal("unsafe output accepted")
				}
				if !strings.Contains(err.Error(), path) {
					t.Errorf("error omits path: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				info, err := file.Stat()
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
					t.Errorf("descriptor permissions before write: %o", info.Mode().Perm())
				}
				_, err = file.WriteString("new")
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("write=%v, close=%v", err, closeErr)
				}
			}
			if test.directory {
				return
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			want := "new"
			if test.symlink {
				want = "prior"
			} else if test.append && test.existing {
				want = "priornew"
			}
			if diff := cmp.Diff(want, string(got)); diff != "" {
				t.Errorf("contents (-want +got):\n%s", diff)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" {
				wantMode := os.FileMode(0o600)
				if test.symlink {
					wantMode = 0o644
				}
				if diff := cmp.Diff(wantMode, info.Mode().Perm()); diff != "" {
					t.Errorf("permissions (-want +got):\n%s", diff)
				}
			}
		})
	}
}
