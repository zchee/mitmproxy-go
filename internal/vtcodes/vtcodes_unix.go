// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package vtcodes

import (
	"os"

	"golang.org/x/sys/unix"
)

// isSupported reports whether f is a terminal, as Python's isatty does: the
// terminal attributes of the descriptor can be read.
func isSupported(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	return err == nil
}

// columns returns the window width of the terminal behind f.
func columns(f *os.File) (int, bool) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, false
	}
	return int(ws.Col), true
}
