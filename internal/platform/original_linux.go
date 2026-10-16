// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package platform

import (
	"context"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/zchee/mitmproxy-go/connection"
)

func originalAddr(ctx context.Context, conn *net.TCPConn) (connection.Address, error) {
	local, err := tcpAddress(conn.LocalAddr())
	if err != nil {
		return connection.Address{}, err
	}
	ipv4 := local.Addr().Unmap().Is4()
	level, size := unix.SOL_IPV6, 28
	if ipv4 {
		level, size = unix.SOL_IP, 16
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return connection.Address{}, fmt.Errorf("TCP descriptor: %w", err)
	}
	var buf [28]byte
	length := uint32(size)
	var syscallErr error
	err = raw.Control(func(fd uintptr) {
		if syscallErr = ctx.Err(); syscallErr != nil {
			return
		}
		// The buffers live for the entire syscall and fd is borrowed only inside Control.
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(level), 80, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&length)), 0) //nolint:gosec // Fixed live sockaddr/socklen buffers and descriptor borrowed only within Control.
		if errno != 0 {
			syscallErr = errno
		}
	})
	if err != nil {
		return connection.Address{}, fmt.Errorf("TCP descriptor control: %w", err)
	}
	if syscallErr != nil {
		return connection.Address{}, fmt.Errorf("SO_ORIGINAL_DST: %w", syscallErr)
	}
	if length != uint32(size) {
		return connection.Address{}, ErrInvalidAddress
	}
	return decodeSockaddr(buf[:size], ipv4)
}
