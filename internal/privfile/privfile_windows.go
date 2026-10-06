// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package privfile

import (
	"errors"
	"os"
	"syscall"
)

func openPrivate(path string, appendMode bool) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
		if !ok || info.Mode()&os.ModeSymlink != 0 || attributes.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, &os.PathError{Op: "open private output", Path: path, Err: errors.New("symlink or reparse point refused")}
		}
		if !info.Mode().IsRegular() {
			return nil, &os.PathError{Op: "open private output", Path: path, Err: errors.New("not a regular file")}
		}
	}
	// Windows does not enforce Unix modes. The pre-open check cannot prevent a
	// directory entry being replaced between Lstat and OpenFile.
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if appendMode {
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	return os.OpenFile(path, flags, 0o600) //nolint:gosec // Operator-selected output with pre-existing reparse points rejected above.
}
