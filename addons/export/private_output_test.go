// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package export

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestPrivateOutputPaths(t *testing.T) {
	tests := map[string]struct{ symlink, foreign bool }{
		"success: narrow existing file": {},
		"error: symlink refused":        {symlink: true},
		"error: foreign owner refused":  {foreign: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TFlow(testflow.WithResponse)
			data, err := rawRequest(f)
			if err != nil {
				t.Fatal(err)
			}
			payload := string(data)
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
			err = New(options.New()).file(t.Context(), "raw_request", f, command.Path(path))
			refused := test.symlink || test.foreign
			if err != nil {
				t.Fatal(err)
			}
			want := payload
			if refused {
				want = seed
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
