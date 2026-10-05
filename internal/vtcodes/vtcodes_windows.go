// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package vtcodes

import (
	"os"

	"golang.org/x/sys/windows"
)

// isSupported ports the Windows branch of upstream's ensure_supported: f
// must be a console (GetConsoleMode succeeds, the isatty check) and must be
// the process's standard output or standard error, and enabling virtual
// terminal processing on that console must succeed. Enabling it is a side
// effect upstream relies on for colour output.
func isSupported(f *os.File) bool {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	if f != os.Stdout && f != os.Stderr {
		return false
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}

// columns returns the window width of the console behind f, as Python's
// os.get_terminal_size does on Windows.
func columns(f *os.File) (int, bool) {
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(f.Fd()), &info); err != nil {
		return 0, false
	}
	return int(info.Window.Right - info.Window.Left + 1), true
}
