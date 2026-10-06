// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build unix

package privfile

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openPrivate(path string, appendMode bool) (_ *os.File, err error) {
	flags := os.O_WRONLY | os.O_CREATE | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if appendMode {
		flags |= os.O_APPEND
	}
	// Nonblocking open lets us reject a FIFO rather than wait for a reader.
	file, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // Operator-selected output, validated through its descriptor before modification.
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, &os.PathError{Op: "open private output", Path: path, Err: fmt.Errorf("symlink refused: %w", unix.ELOOP)}
		}
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	var stat unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, &os.PathError{Op: "stat private output", Path: path, Err: err}
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, &os.PathError{Op: "open private output", Path: path, Err: errors.New("not a regular file")}
	}
	if stat.Uid != uint32(os.Geteuid()) { //nolint:gosec // Unix effective uid is a nonnegative uid_t.
		return nil, &os.PathError{Op: "open private output", Path: path, Err: errors.New("file owner is not the effective user")}
	}
	if err = file.Chmod(0o600); err != nil {
		return nil, err
	}
	if !appendMode {
		if err = file.Truncate(0); err != nil {
			return nil, err
		}
	}
	return file, nil
}
