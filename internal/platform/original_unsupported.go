// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !freebsd && !openbsd

package platform

import (
	"context"
	"net"
	"runtime"

	"github.com/zchee/mitmproxy-go/connection"
)

func originalAddr(_ context.Context, _ *net.TCPConn) (connection.Address, error) {
	return connection.Address{}, checkOS(runtime.GOOS)
}
