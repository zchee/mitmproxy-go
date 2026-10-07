// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package freeport finds a port that is free for TCP or both TCP and UDP,
// as mitmproxy's mitmproxy/net/free_port.py does for the paired protocols.
package freeport

import (
	"context"
	"net"
	"strconv"
)

// attempts is how many ports the helpers try before they give up.
const attempts = 64

type listeners struct {
	listen       func(context.Context, string, string) (net.Listener, error)
	listenPacket func(context.Context, string, string) (net.PacketConn, error)
}

// GetFreePort returns a port on which both a TCP and a UDP socket could be
// bound on all IPv4 interfaces. It never fails: if no such port is found
// it returns 0.
//
// The port is released before GetFreePort returns, so another process can
// take it before the caller binds it.
func GetFreePort() int {
	lc := &net.ListenConfig{}
	return getFreePort(context.Background(), listeners{listen: lc.Listen, listenPacket: lc.ListenPacket})
}

// GetFreeTCPPort returns a port on which a TCP socket could be bound on all
// IPv4 interfaces, without requiring a UDP socket on the same port. It never
// fails: if no such port is found it returns 0.
//
// The port is released before GetFreeTCPPort returns, so another process can
// take it before the caller binds it.
func GetFreeTCPPort() int {
	lc := &net.ListenConfig{}
	return getFreeTCPPort(context.Background(), listeners{listen: lc.Listen, listenPacket: lc.ListenPacket})
}

func getFreeTCPPort(ctx context.Context, lc listeners) int {
	for range attempts {
		tcp, err := lc.listen(ctx, "tcp4", ":0")
		if err != nil {
			continue
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		// Closing a listener that accepted nothing cannot lose data.
		_ = tcp.Close()
		return port
	}
	return 0
}

func getFreePort(ctx context.Context, lc listeners) int {
	for range attempts {
		if port, ok := tryPort(ctx, lc); ok {
			return port
		}
	}
	return 0
}

// tryPort binds a TCP socket to an ephemeral port and checks that a UDP
// socket can be bound to the same port.
func tryPort(ctx context.Context, lc listeners) (int, bool) {
	tcp, err := lc.listen(ctx, "tcp4", ":0")
	if err != nil {
		return 0, false
	}
	// Closing a listener that accepted nothing cannot lose data.
	defer func() { _ = tcp.Close() }()
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := lc.listenPacket(ctx, "udp4", ":"+strconv.Itoa(port))
	if err != nil {
		return 0, false
	}
	if err := udp.Close(); err != nil {
		return 0, false
	}
	return port, true
}
