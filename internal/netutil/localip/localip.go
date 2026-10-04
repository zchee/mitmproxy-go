// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package localip finds the local address the operating system would use
// for outgoing traffic, as mitmproxy's mitmproxy/net/local_ip.py does.
package localip

import (
	"fmt"
	"net"
	"net/netip"
)

// Family selects the IP version of the address GetLocalIP returns.
type Family int

// The address families GetLocalIP supports.
const (
	IPv4 Family = iota
	IPv6
)

// The default destinations whose route GetLocalIP asks about: Google
// Public DNS, as upstream uses.
const (
	DefaultReachable4 = "8.8.8.8"
	DefaultReachable6 = "2001:4860:4860::8888"
)

// GetLocalIP returns the local address of the default outgoing route for
// family, found by routing towards Google Public DNS.
func GetLocalIP(family Family) (netip.Addr, error) {
	if family == IPv6 {
		return GetLocalIPVia(family, DefaultReachable6)
	}
	return GetLocalIPVia(family, DefaultReachable4)
}

// GetLocalIPVia returns the local address the operating system picks for
// traffic to reachable, a host name or an address of the given family.
//
// It connects a UDP socket, which selects a route and source address but
// sends no packets; resolving a host name may still query DNS. It fails if
// the destination is known to be unreachable.
func GetLocalIPVia(family Family, reachable string) (netip.Addr, error) {
	network := "udp4"
	if family == IPv6 {
		network = "udp6"
	}
	conn, err := net.Dial(network, net.JoinHostPort(reachable, "80"))
	if err != nil {
		return netip.Addr{}, err
	}
	// The socket never sent anything, so a close error carries no information.
	defer func() { _ = conn.Close() }()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("localip: unexpected local address type %T", conn.LocalAddr())
	}
	return local.AddrPort().Addr().Unmap(), nil
}
