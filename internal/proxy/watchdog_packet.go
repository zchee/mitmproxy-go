// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"net"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// UDP hook waits suppress expiry, but do not move the last-datagram baseline.
func newPacketWatchdog(clock watchdogClock, expire func()) *watchdog {
	w := newWatchdog(layer.UDPIdleTimeout, clock, expire)
	w.mu.Lock()
	w.keepDeadline = true
	w.mu.Unlock()
	return w
}

type activityPackets struct {
	layer.PacketTransport
	watchdog *watchdog
}

// ReadFrom forwards a datagram read and records idle activity only when it succeeds.
func (c *activityPackets) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketTransport.ReadFrom(p)
	if err == nil {
		c.watchdog.activity()
	}
	return n, addr, err
}

// WriteTo forwards a datagram write and records idle activity only when it succeeds.
func (c *activityPackets) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketTransport.WriteTo(p, addr)
	if err == nil {
		c.watchdog.activity()
	}
	return n, err
}
