// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package vtcodes

import "os"

// isSupported reports no escape-code support on platforms without a
// terminal detection port.
func isSupported(_ *os.File) bool {
	return false
}

// columns reports no terminal width on platforms without a terminal
// detection port.
func columns(_ *os.File) (int, bool) {
	return 0, false
}
