// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func waitLinuxInterceptDrain(ctx context.Context, conn *net.UnixConn, closed <-chan struct{}) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var queued int
		var queueErr error
		err := raw.Control(func(fd uintptr) {
			queued, queueErr = unix.IoctlGetInt(int(fd), unix.TIOCOUTQ)
		})
		if err := errors.Join(err, queueErr); err != nil {
			return err
		}
		if queued == 0 {
			select {
			case <-closed:
				return net.ErrClosed
			default:
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-closed:
			return net.ErrClosed
		case <-ticker.C:
		}
	}
}
