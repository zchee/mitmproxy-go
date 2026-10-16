// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package platform

import (
	"context"
	"net"

	"github.com/zchee/mitmproxy-go/connection"
)

func originalAddr(_ context.Context, conn *net.TCPConn) (connection.Address, error) {
	a, err := tcpAddress(conn.LocalAddr())
	if err != nil {
		return connection.Address{}, err
	}
	return connection.Address{Host: a.Addr().String(), Port: int(a.Port())}, nil
}
