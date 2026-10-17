// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package processinfo

func visibleProcessIDs() (map[int32]struct{}, error) {
	return map[int32]struct{}{}, nil
}

// ExecutableIcon reports that executable icons are unsupported on Linux.
func ExecutableIcon(string) ([]byte, error) {
	return nil, &UnsupportedError{Operation: "executable icons", Platform: "linux"}
}
