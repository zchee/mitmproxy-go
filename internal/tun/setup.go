// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"errors"
	"syscall"
)

// setupOps isolates the kernel calls so ownership and the unprivileged retry can
// be exercised on hosts without a TUN device.
type setupOps struct {
	open      func() (int, error)
	close     func(int) error
	attach    func(int, string) (string, error)
	configure func(string) error
}

func setupDevice(name string, ops setupOps) (int, string, bool, error) {
	fd, err := ops.open()
	if err != nil {
		return -1, "", false, err
	}
	actual, err := ops.attach(fd, name)
	if err == nil {
		err = ops.configure(actual)
	}
	if err == nil {
		return fd, actual, true, nil
	}
	closeErr := ops.close(fd)
	if !errors.Is(err, syscall.EPERM) || name == "" || closeErr != nil {
		return -1, "", false, errors.Join(err, closeErr)
	}
	fd, err = ops.open()
	if err != nil {
		return -1, "", false, err
	}
	actual, err = ops.attach(fd, name)
	if err != nil {
		return -1, "", false, errors.Join(err, ops.close(fd))
	}
	return fd, actual, false, nil
}
