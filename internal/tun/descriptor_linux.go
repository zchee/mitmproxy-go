// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"errors"

	"golang.org/x/sys/unix"
)

func duplicateDescriptor(fd int) (int, error) {
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.SetNonblock(duplicate, true); err != nil {
		return -1, errors.Join(err, unix.Close(duplicate))
	}
	return duplicate, nil
}
