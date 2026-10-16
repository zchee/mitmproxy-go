// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !darwin && !linux && !windows

package processinfo

import "runtime"

// ActiveExecutables reports that process listing is unsupported on this OS.
func ActiveExecutables() ([]Process, error) {
	return nil, &UnsupportedError{Operation: "process listing", Platform: runtime.GOOS}
}

// ExecutableIcon reports that executable icons are unsupported on this OS.
func ExecutableIcon(string) ([]byte, error) {
	return nil, &UnsupportedError{Operation: "executable icons", Platform: runtime.GOOS}
}
