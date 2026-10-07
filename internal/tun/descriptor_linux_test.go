// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package tun

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDuplicateDescriptor(t *testing.T) {
	tests := map[string]struct{ invalid bool }{
		"success: close on exec and shared description": {},
		"error: invalid original":                       {invalid: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := descriptorCount(t)
			t.Cleanup(func() {
				if after := descriptorCount(t); after != before {
					t.Errorf("descriptor count after cleanup = %d, want %d", after, before)
				}
			})
			fd := -1
			var pipe [2]int
			if !tt.invalid {
				if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
					t.Fatal(err)
				}
				fd = pipe[0]
				t.Cleanup(func() {
					if pipe[0] >= 0 {
						_ = unix.Close(pipe[0])
					}
					_ = unix.Close(pipe[1])
				})
			}
			duplicate, err := duplicateDescriptor(fd)
			if tt.invalid {
				if !errors.Is(err, unix.EBADF) {
					t.Fatalf("duplicate error = %v, want EBADF", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(duplicate) })
			flags, err := unix.FcntlInt(uintptr(duplicate), unix.F_GETFD, 0)
			if err != nil {
				t.Fatal(err)
			}
			if flags&unix.FD_CLOEXEC == 0 {
				t.Error("duplicate is inherited by child processes")
			}
			status, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			if status&unix.O_NONBLOCK == 0 {
				t.Error("original and duplicate must share nonblocking file description")
			}
			if err := unix.Close(fd); err != nil {
				t.Fatal(err)
			}
			pipe[0] = -1
			if _, err := unix.Write(pipe[1], []byte{42}); err != nil {
				t.Fatal(err)
			}
			var buf [1]byte
			if n, err := unix.Read(duplicate, buf[:]); err != nil || n != 1 || buf[0] != 42 {
				t.Fatalf("read from duplicate after closing original = %d, %v, %v", n, buf, err)
			}
		})
	}
}

func descriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
