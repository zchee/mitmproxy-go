// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package netstack accepts IP packets addressed to arbitrary destinations.
package netstack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	mtu                         = 1420
	tcpBufferSize               = 64 * 1024
	packetQueueSize             = 256
	nicID           tcpip.NICID = 1
)

func newGVisor(clock tcpip.Clock) (*stack.Stack, *channel.Endpoint, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		Clock:              clock,
	})
	link := channel.New(packetQueueSize, mtu, "")
	fail := func(err tcpip.Error) (*stack.Stack, *channel.Endpoint, error) {
		link.Close()
		s.Destroy()
		return nil, nil, fmt.Errorf("configure IP stack: %s", err)
	}
	if err := s.CreateNIC(nicID, link); err != nil {
		return fail(err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return fail(err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return fail(err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{Min: tcpBufferSize, Default: tcpBufferSize, Max: tcpBufferSize}); err != nil {
		return fail(err)
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{Min: tcpBufferSize, Default: tcpBufferSize, Max: tcpBufferSize}); err != nil {
		return fail(err)
	}
	return s, link, nil
}
