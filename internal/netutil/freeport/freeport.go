// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package freeport finds a port that is free for TCP or both TCP and UDP,
// as mitmproxy's mitmproxy/net/free_port.py does for the paired protocols.
package freeport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// attempts is how many ports the helpers try before they give up.
const attempts = 64

type listeners struct {
	listen       func(context.Context, string, string) (net.Listener, error)
	listenPacket func(context.Context, string, string) (net.PacketConn, error)
	excluded     func(int, bool) bool
}

// GetFreePort returns a port on which both a TCP and a UDP socket could be
// bound on all IPv4 interfaces. It never fails: if no such port is found
// it returns 0.
//
// The port is released before GetFreePort returns, so another process can
// take it before the caller binds it.
func GetFreePort() int {
	port, _ := FreePort()
	return port
}

// FreePort returns an available port for TCP and UDP on all IPv4 interfaces.
// On Windows, cached TCP and UDP excluded port ranges are skipped when readable.
// It returns the last TCP and UDP candidate errors if every port is rejected.
// Rejected TCP candidates remain reserved until selection ends, so an ephemeral
// allocator cannot repeatedly choose the same UDP-busy port. At most 64 TCP
// listeners are retained, and every reservation is released before returning.
// Another process can take the selected port before the caller binds it.
func FreePort() (int, error) {
	lc := &net.ListenConfig{}
	return getFreePort(context.Background(), listeners{listen: lc.Listen, listenPacket: lc.ListenPacket, excluded: isExcludedPort})
}

// GetFreeTCPPort returns a port on which a TCP socket could be bound on all
// IPv4 interfaces, without requiring a UDP socket on the same port. It never
// fails: if no such port is found it returns 0. Readable Windows TCP excluded
// port ranges are cached once and skipped.
//
// The port is released before GetFreeTCPPort returns, so another process can
// take it before the caller binds it.
func GetFreeTCPPort() int {
	lc := &net.ListenConfig{}
	return getFreeTCPPort(context.Background(), listeners{listen: lc.Listen, listenPacket: lc.ListenPacket, excluded: isExcludedPort})
}

func getFreeTCPPort(ctx context.Context, lc listeners) int {
	var rejected []net.Listener
	defer func() {
		for _, tcp := range rejected {
			_ = tcp.Close()
		}
	}()
	for range attempts {
		tcp, err := lc.listen(ctx, "tcp4", ":0")
		if err != nil {
			continue
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		if lc.excluded != nil && lc.excluded(port, false) {
			rejected = append(rejected, tcp)
			continue
		}
		// Closing a listener that accepted nothing cannot lose data.
		_ = tcp.Close()
		return port
	}
	return 0
}

func getFreePort(ctx context.Context, lc listeners) (int, error) {
	var rejected []net.Listener
	defer func() {
		for _, tcp := range rejected {
			_ = tcp.Close()
		}
	}()
	var lastTCP, lastUDP error
	for range attempts {
		tcp, err := lc.listen(ctx, "tcp4", ":0")
		if err != nil {
			lastTCP = fmt.Errorf("TCP bind: %w", err)
			continue
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		if lc.excluded != nil && lc.excluded(port, true) {
			lastUDP = fmt.Errorf("port %d is in a Windows excluded TCP/UDP range", port)
			rejected = append(rejected, tcp)
			continue
		}
		udp, err := lc.listenPacket(ctx, "udp4", ":"+strconv.Itoa(port))
		if err != nil {
			lastUDP = fmt.Errorf("UDP bind: %w", err)
			rejected = append(rejected, tcp)
			continue
		}
		if err := udp.Close(); err != nil {
			lastUDP = fmt.Errorf("UDP close: %w", err)
			rejected = append(rejected, tcp)
			continue
		}
		// No connection was accepted, so closing cannot lose application data.
		_ = tcp.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no paired TCP/UDP port after %d attempts: %w", attempts, errors.Join(lastTCP, lastUDP))
}
