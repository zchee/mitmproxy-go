// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build unix

package privfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestForeignOwner(t *testing.T) {
	tests := map[string]struct {
		open func(string) (*os.File, error)
	}{
		"error: overwrite foreign owner": {Create},
		"error: append foreign owner":    {Append},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "foreign")
			if err := os.WriteFile(path, []byte("prior"), 0o600); err != nil {
				t.Fatal(err)
			}
			uid := 0
			if os.Geteuid() == 0 {
				uid = 1
			}
			if err := os.Chown(path, uid, -1); err != nil {
				t.Skipf("cannot create a foreign-owned file: %v", err)
			}
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
			file, err := test.open(path)
			if err == nil {
				_ = file.Close()
				t.Fatal("foreign-owned file accepted")
			}
			if !strings.Contains(err.Error(), "owner") || !strings.Contains(err.Error(), path) {
				t.Errorf("unexplained refusal: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "prior" {
				t.Fatalf("contents=%q, error=%v", got, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o666 {
				t.Fatalf("foreign permissions changed: %v, %v", info, err)
			}
		})
	}
}

func TestFIFORefused(t *testing.T) {
	tests := map[string]struct {
		open func(string) (*os.File, error)
	}{
		"error: overwrite FIFO": {Create},
		"error: append FIFO":    {Append},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fifo")
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := test.open(path)
			if err == nil {
				_ = file.Close()
				t.Fatal("FIFO accepted")
			}
		})
	}
}
