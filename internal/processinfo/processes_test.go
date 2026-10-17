// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestProcessSnapshot(t *testing.T) {
	tests := map[string]struct{ canceled bool }{
		"current_executable": {},
		"canceled":           {canceled: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.canceled {
				cancel()
			}
			got, err := snapshotProcesses(ctx)
			if test.canceled {
				if !errors.Is(err, context.Canceled) || got != nil {
					t.Fatalf("got %v, %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			executable, err = filepath.EvalSymlinks(executable)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for index, entry := range got {
				if index > 0 && got[index-1].PID >= entry.PID {
					t.Fatalf("unsorted or repeated PID: %v", got)
				}
				if entry.Executable == "" {
					t.Fatal("empty executable")
				}
				if entry.PID != int32(os.Getpid()) {
					continue
				}
				found = true
				resolved, err := filepath.EvalSymlinks(entry.Executable)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(executable, resolved); diff != "" {
					t.Fatalf("current executable (-want +got):\n%s", diff)
				}
				if runtime.GOOS != "windows" && (!entry.UIDKnown || entry.UID != uint32(os.Getuid())) {
					t.Fatalf("real UID mismatch: %+v", entry)
				}
			}
			if !found {
				t.Fatal("current process absent")
			}
		})
	}
}

func TestProcessSnapshotOwnership(t *testing.T) {
	first, err := snapshotProcesses(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("empty process snapshot")
	}
	first[0].Executable = ""
	second, err := snapshotProcesses(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range second {
		if entry.Executable == "" {
			t.Fatal("caller mutation leaked into next snapshot")
		}
	}
}
