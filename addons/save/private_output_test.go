// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package save

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestPrivateOutputPaths(t *testing.T) {
	tests := map[string]struct{ append, symlink, foreign, stream bool }{
		"success: narrow existing file":            {},
		"error: symlink refused":                   {symlink: true},
		"error: foreign owner refused":             {foreign: true},
		"success: append preserves content":        {append: true},
		"error: append symlink refused":            {append: true, symlink: true},
		"error: append foreign owner refused":      {append: true, foreign: true},
		"success: stream overwrite narrows file":   {stream: true},
		"success: stream append preserves content": {stream: true, append: true},
		"error: stream symlink refused":            {stream: true, symlink: true},
		"error: stream append symlink refused":     {stream: true, append: true, symlink: true},
		"error: stream foreign owner refused":      {stream: true, foreign: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TFlow(testflow.WithResponse)
			var recording bytes.Buffer
			if err := flowio.NewWriter(&recording).Add(f); err != nil {
				t.Fatal(err)
			}
			payload := recording.String()
			s, manager := setup(t, nil)
			seed := payload
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
			spec := path
			if test.append {
				spec = "+" + spec
			}
			var err error
			if test.stream {
				err = configure(t, manager, map[string]any{"save_stream_file": new(spec)})
				if err == nil {
					err = s.Response(t.Context(), f)
				}
				if err == nil {
					err = s.Done(t.Context())
				}
			} else {
				err = s.save(t.Context(), []flow.Flow{f}, command.Path(spec))
			}
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
