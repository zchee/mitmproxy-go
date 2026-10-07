// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package netstack accepts IP packets addressed to arbitrary destinations.
package netstack

import (
	"context"
	"fmt"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
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

type ipEngine struct {
	stack *stack.Stack
	link  *channel.Endpoint
}

func newStack(parent context.Context, clock tcpip.Clock) (*Stack, error) {
	engine, link, err := newGVisor(clock)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Stack{
		ctx: ctx, cancel: cancel,
		engine: &ipEngine{stack: engine, link: link},
		input:  make(chan inboundPacket, packetQueueSize),
		output: make(chan []byte, packetQueueSize),
		tcp:    make(chan *Stream, packetQueueSize),
		udp:    make(chan layer.PacketTransport, packetQueueSize),
		done:   make(chan struct{}),
	}
	go s.run()
	return s, nil
}

func checkedIPPacket(packet []byte) ([]byte, error) {
	if len(packet) == 0 || len(packet) > 65575 {
		return nil, ErrInvalidPacket
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < header.IPv4MinimumSize {
			return nil, ErrInvalidPacket
		}
		ip := header.IPv4(packet)
		if !ip.IsValid(len(packet)) || !ip.IsChecksumValid() {
			return nil, ErrInvalidPacket
		}
		return packet[:ip.TotalLength()], nil
	case 6:
		if len(packet) < header.IPv6MinimumSize {
			return nil, ErrInvalidPacket
		}
		ip := header.IPv6(packet)
		if !ip.IsValid(len(packet)) {
			return nil, ErrInvalidPacket
		}
		return packet[:header.IPv6MinimumSize+int(ip.PayloadLength())], nil
	default:
		return nil, ErrInvalidPacket
	}
}

func (e *ipEngine) inject(packet []byte) []byte {
	protocol := header.IPv4ProtocolNumber
	if packet[0]>>4 == 6 {
		protocol = header.IPv6ProtocolNumber
		if packet[6] == byte(header.ICMPv6ProtocolNumber) {
			return echoReply(packet)
		}
	} else if header.IPv4(packet).Protocol() == uint8(header.ICMPv4ProtocolNumber) {
		return echoReply(packet)
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	defer p.DecRef()
	e.link.InjectInbound(protocol, p)
	return nil
}

func echoReply(packet []byte) []byte {
	if packet[0]>>4 == 4 {
		ip := header.IPv4(packet)
		if ip.FragmentOffset() != 0 || ip.Flags()&header.IPv4FlagMoreFragments != 0 {
			return nil
		}
		payload := packet[ip.HeaderLength():]
		if len(payload) < header.ICMPv4MinimumSize || payload[0] != byte(header.ICMPv4Echo) || checksum.Checksum(payload, 0) != 0xffff {
			return nil
		}
		reply := make([]byte, header.IPv4MinimumSize+len(payload))
		out := header.IPv4(reply)
		out.Encode(&header.IPv4Fields{TotalLength: uint16(len(reply)), TTL: 255, Protocol: uint8(header.ICMPv4ProtocolNumber), SrcAddr: ip.DestinationAddress(), DstAddr: ip.SourceAddress()})
		out.SetChecksum(^out.CalculateChecksum())
		copy(reply[header.IPv4MinimumSize:], payload)
		icmp := header.ICMPv4(reply[header.IPv4MinimumSize:])
		icmp.SetType(header.ICMPv4EchoReply)
		icmp.SetChecksum(0)
		icmp.SetChecksum(^checksum.Checksum(icmp, 0))
		return reply
	}
	ip := header.IPv6(packet)
	payload := packet[header.IPv6MinimumSize:]
	if len(payload) < header.ICMPv6EchoMinimumSize || payload[0] != byte(header.ICMPv6EchoRequest) {
		return nil
	}
	icmp := header.ICMPv6(payload)
	if header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: ip.SourceAddress(), Dst: ip.DestinationAddress()}) != icmp.Checksum() {
		return nil
	}
	reply := make([]byte, header.IPv6MinimumSize+len(payload))
	header.IPv6(reply).Encode(&header.IPv6Fields{PayloadLength: uint16(len(payload)), HopLimit: 255, TransportProtocol: header.ICMPv6ProtocolNumber, SrcAddr: ip.DestinationAddress(), DstAddr: ip.SourceAddress()})
	copy(reply[header.IPv6MinimumSize:], payload)
	out := header.ICMPv6(reply[header.IPv6MinimumSize:])
	out.SetType(header.ICMPv6EchoReply)
	out.SetChecksum(0)
	out.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: out, Src: ip.DestinationAddress(), Dst: ip.SourceAddress()}))
	return reply
}

func (e *ipEngine) readPacket(ctx context.Context) []byte {
	p := e.link.ReadContext(ctx)
	if p == nil {
		return nil
	}
	defer p.DecRef()
	b := p.ToBuffer()
	defer b.Release()
	return b.Flatten()
}

func (e *ipEngine) close() {
	e.link.Close()
	e.stack.Destroy()
}
