// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package freeport finds a port that is free for both TCP and UDP, as
// mitmproxy's mitmproxy/net/free_port.py does.
package freeport

import (
	"context"
	"net"
	"strconv"
)

// attempts is how many ports GetFreePort tries before it gives up.
const attempts = 10

// GetFreePort returns a port on which both a TCP and a UDP socket could be
// bound on all IPv4 interfaces. It never fails: if no such port is found
// it returns 0.
//
// The port is released before GetFreePort returns, so another process can
// take it before the caller binds it.
func GetFreePort() int {
	return getFreePort(context.Background(), &net.ListenConfig{})
}

func getFreePort(ctx context.Context, lc *net.ListenConfig) int {
	for range attempts {
		if port, ok := tryPort(ctx, lc); ok {
			return port
		}
	}
	return 0
}

// tryPort binds a TCP socket to an ephemeral port and checks that a UDP
// socket can be bound to the same port.
func tryPort(ctx context.Context, lc *net.ListenConfig) (int, bool) {
	tcp, err := lc.Listen(ctx, "tcp4", ":0")
	if err != nil {
		return 0, false
	}
	// Closing a listener that accepted nothing cannot lose data.
	defer func() { _ = tcp.Close() }()
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := lc.ListenPacket(ctx, "udp4", ":"+strconv.Itoa(port))
	if err != nil {
		return 0, false
	}
	if err := udp.Close(); err != nil {
		return 0, false
	}
	return port, true
}
