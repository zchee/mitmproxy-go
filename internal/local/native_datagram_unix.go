// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package local

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func connectNativeDatagram(conn *net.UnixConn, path string) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var connectErr error
	err = raw.Control(func(fd uintptr) {
		connectErr = unix.Connect(int(fd), &unix.SockaddrUnix{Name: path})
	})
	return errors.Join(err, connectErr)
}

func nativeDatagramTruncated(flags int) bool { return flags&unix.MSG_TRUNC != 0 }
