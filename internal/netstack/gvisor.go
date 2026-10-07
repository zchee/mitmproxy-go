// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package netstack accepts IP packets addressed to arbitrary destinations.
package netstack

import (
	"container/list"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

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
		// The virtual NIC carries tunnel traffic, including host-loopback destinations.
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true}),
		},
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
	stack       *stack.Stack
	link        *channel.Endpoint
	owner       *Stack
	currentInfo map[string]any
	mu          sync.Mutex
	closed      bool
	handlers    sync.WaitGroup
	workers     sync.WaitGroup
	pendingTCP  map[stack.TransportEndpointID]map[string]any
	tcp         map[stack.TransportEndpointID]*tcpForwardState
	udp         map[stack.TransportEndpointID]*udpForwardState
	udpLRU      list.List
}

type tcpForwardState struct {
	stream  *Stream
	conn    *gonet.TCPConn
	queue   *waiter.Queue
	entry   waiter.Entry
	timer   tcpip.Timer
	expires time.Time
	cancel  context.CancelFunc
}

type udpForwardState struct {
	transport *udpTransport
	timer     tcpip.Timer
	expires   time.Time
	element   *list.Element
}

const (
	flowLimit         = 1024
	flowIdleTimeout   = 60 * time.Second
	keepaliveInterval = 28 * time.Second
)

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
	s.engine.owner = s
	s.engine.pendingTCP = make(map[stack.TransportEndpointID]map[string]any)
	s.engine.tcp = make(map[stack.TransportEndpointID]*tcpForwardState)
	s.engine.udp = make(map[stack.TransportEndpointID]*udpForwardState)
	forwarder := tcp.NewForwarder(engine, tcpBufferSize, flowLimit, s.engine.forwardTCP)
	engine.SetTransportProtocolHandler(tcp.ProtocolNumber, func(id stack.TransportEndpointID, p *stack.PacketBuffer) bool {
		headerBytes := p.TransportHeader().Slice()
		if len(headerBytes) < 20 || headerBytes[13]&byte(header.TCPFlagSyn) == 0 || headerBytes[13]&byte(header.TCPFlagAck) != 0 {
			return false
		}
		s.engine.mu.Lock()
		if s.engine.closed || len(s.engine.pendingTCP)+len(s.engine.tcp)+len(s.engine.udp) >= flowLimit {
			s.engine.mu.Unlock()
			return true
		}
		if _, ok := s.engine.pendingTCP[id]; !ok {
			s.engine.pendingTCP[id] = s.engine.currentInfo
		}
		s.engine.mu.Unlock()
		handled := forwarder.HandlePacket(id, p)
		if !handled {
			s.engine.mu.Lock()
			delete(s.engine.pendingTCP, id)
			s.engine.mu.Unlock()
		}
		return handled
	})
	udpForwarder := udp.NewForwarder(engine, s.engine.forwardUDP)
	engine.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
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

func (e *ipEngine) inject(inbound inboundPacket) []byte {
	packet := inbound.bytes
	e.currentInfo = inbound.extraInfo
	e.touchPacket(packet)
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

func (e *ipEngine) forwardTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	e.mu.Lock()
	if e.closed {
		delete(e.pendingTCP, id)
		e.mu.Unlock()
		r.Complete(false)
		return
	}
	info := e.pendingTCP[id]
	e.handlers.Add(1)
	e.mu.Unlock()
	defer e.handlers.Done()
	var q waiter.Queue
	ep, err := r.CreateEndpoint(&q)
	r.Complete(false)
	if err != nil {
		e.mu.Lock()
		delete(e.pendingTCP, id)
		e.mu.Unlock()
		return
	}
	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(keepaliveInterval)
	interval := tcpip.KeepaliveIntervalOption(keepaliveInterval)
	if err := ep.SetSockOpt(&idle); err != nil {
		ep.Close()
		e.mu.Lock()
		delete(e.pendingTCP, id)
		e.mu.Unlock()
		return
	}
	if err := ep.SetSockOpt(&interval); err != nil {
		ep.Close()
		e.mu.Lock()
		delete(e.pendingTCP, id)
		e.mu.Unlock()
		return
	}
	conn := gonet.NewTCPConn(&q, ep)
	entry, writable := waiter.NewChannelEntry(waiter.EventOut | waiter.EventErr | waiter.EventHUp)
	ctx, cancel := context.WithCancel(e.owner.ctx)
	stream := newStream(ctx, conn, func() (bool, <-chan struct{}, error) {
		return ep.Readiness(waiter.EventOut) != 0, writable, nil
	}, info)
	state := &tcpForwardState{stream: stream, conn: conn, queue: &q, entry: entry, cancel: cancel}
	q.EventRegister(&state.entry)
	e.mu.Lock()
	delete(e.pendingTCP, id)
	if e.closed {
		e.mu.Unlock()
		cancel()
		_ = conn.Close()
		<-stream.done
		q.EventUnregister(&state.entry)
		return
	}
	state.expires = e.stack.Clock().Now().Add(flowIdleTimeout)
	state.timer = e.stack.Clock().AfterFunc(flowIdleTimeout, func() { e.expireTCP(id, state) })
	e.tcp[id] = state
	e.workers.Add(1)
	e.mu.Unlock()
	go func() { defer e.workers.Done(); <-stream.done }()
	select {
	case e.owner.tcp <- stream:
	case <-e.owner.ctx.Done():
		e.removeTCP(id, state, false)
	default:
		e.removeTCP(id, state, false)
	}
}

func (e *ipEngine) expireTCP(id stack.TransportEndpointID, state *tcpForwardState) {
	e.removeTCP(id, state, true)
}

func (e *ipEngine) removeTCP(id stack.TransportEndpointID, state *tcpForwardState, expired bool) {
	e.mu.Lock()
	if e.tcp[id] != state || expired && (e.closed || e.stack.Clock().Now().Before(state.expires)) {
		e.mu.Unlock()
		return
	}
	delete(e.tcp, id)
	state.timer.Stop()
	e.mu.Unlock()
	state.cancel()
	_ = state.conn.Close()
	<-state.stream.done
	state.queue.EventUnregister(&state.entry)
}

func (e *ipEngine) forwardUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return false
	}
	var evicted *udpTransport
	if len(e.pendingTCP)+len(e.tcp)+len(e.udp) >= flowLimit {
		if back := e.udpLRU.Back(); back != nil {
			evicted = e.udp[back.Value.(stack.TransportEndpointID)].transport
		} else {
			e.mu.Unlock()
			return false
		}
	}
	info := e.currentInfo
	e.mu.Unlock()
	if evicted != nil {
		_ = evicted.Close()
	}
	var q waiter.Queue
	ep, err := r.CreateEndpoint(&q)
	if err != nil {
		return true
	}
	conn := gonet.NewUDPConn(&q, ep)
	state := &udpForwardState{}
	transport := newUDPTransport(e.owner.ctx, conn, conn.RemoteAddr(), info, func() { e.touchUDP(id, state) }, func() { e.removeUDP(id, state) })
	state.transport = transport
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		_ = conn.Close()
		return true
	}
	state.expires = e.stack.Clock().Now().Add(flowIdleTimeout)
	state.timer = e.stack.Clock().AfterFunc(flowIdleTimeout, func() { e.expireUDP(id, state) })
	state.element = e.udpLRU.PushFront(id)
	e.udp[id] = state
	e.workers.Add(1)
	e.mu.Unlock()
	go func() { defer e.workers.Done(); transport.receive() }()
	select {
	case e.owner.udp <- transport:
	case <-e.owner.ctx.Done():
		_ = transport.Close()
	default:
		_ = transport.Close()
	}
	return true
}

func (e *ipEngine) touchUDP(id stack.TransportEndpointID, state *udpForwardState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.udp[id] != state {
		return
	}
	state.expires = e.stack.Clock().Now().Add(flowIdleTimeout)
	state.timer.Reset(flowIdleTimeout)
	e.udpLRU.MoveToFront(state.element)
}

func (e *ipEngine) expireUDP(id stack.TransportEndpointID, state *udpForwardState) {
	e.mu.Lock()
	if e.udp[id] != state || e.closed || e.stack.Clock().Now().Before(state.expires) {
		e.mu.Unlock()
		return
	}
	delete(e.udp, id)
	state.timer.Stop()
	e.udpLRU.Remove(state.element)
	e.mu.Unlock()
	state.transport.closeWithError(ErrStackClosed)
}

func (e *ipEngine) removeUDP(id stack.TransportEndpointID, state *udpForwardState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.udp[id] != state {
		return
	}
	delete(e.udp, id)
	state.timer.Stop()
	e.udpLRU.Remove(state.element)
}

func (e *ipEngine) touchPacket(packet []byte) {
	id, protocol, ok := packetTransportID(packet)
	if !ok {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if protocol == tcp.ProtocolNumber {
		if state := e.tcp[id]; state != nil {
			state.expires = e.stack.Clock().Now().Add(flowIdleTimeout)
			state.timer.Reset(flowIdleTimeout)
		}
	}
	if protocol == udp.ProtocolNumber {
		if state := e.udp[id]; state != nil {
			state.expires = e.stack.Clock().Now().Add(flowIdleTimeout)
			state.timer.Reset(flowIdleTimeout)
			e.udpLRU.MoveToFront(state.element)
		}
	}
}

func packetTransportID(packet []byte) (stack.TransportEndpointID, tcpip.TransportProtocolNumber, bool) {
	var src, dst tcpip.Address
	var payload []byte
	var protocol tcpip.TransportProtocolNumber
	if packet[0]>>4 == 4 {
		ip := header.IPv4(packet)
		if ip.FragmentOffset() != 0 || ip.Flags()&header.IPv4FlagMoreFragments != 0 {
			return stack.TransportEndpointID{}, 0, false
		}
		src, dst = ip.SourceAddress(), ip.DestinationAddress()
		payload = packet[ip.HeaderLength():]
		protocol = tcpip.TransportProtocolNumber(ip.Protocol())
	} else {
		ip := header.IPv6(packet)
		src, dst = ip.SourceAddress(), ip.DestinationAddress()
		payload = packet[40:]
		protocol = tcpip.TransportProtocolNumber(packet[6])
		if protocol != tcp.ProtocolNumber && protocol != udp.ProtocolNumber {
			iterator := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(packet[6]), buffer.MakeWithData(payload))
			defer iterator.Release()
			for {
				h, done, err := iterator.Next()
				if err != nil || done {
					return stack.TransportEndpointID{}, 0, false
				}
				if raw, ok := h.(header.IPv6RawPayloadHeader); ok {
					payload = raw.Buf.Flatten()
					protocol = tcpip.TransportProtocolNumber(raw.Identifier)
					raw.Release()
					break
				}
			}
		}
	}
	if protocol != tcp.ProtocolNumber && protocol != udp.ProtocolNumber {
		return stack.TransportEndpointID{}, 0, false
	}
	if len(payload) < 8 {
		return stack.TransportEndpointID{}, 0, false
	}
	if protocol == tcp.ProtocolNumber && (len(payload) < 20 || int(payload[12]>>4)*4 < 20 || int(payload[12]>>4)*4 > len(payload)) {
		return stack.TransportEndpointID{}, 0, false
	}
	if protocol == udp.ProtocolNumber {
		length := int(binary.BigEndian.Uint16(payload[4:]))
		if length < 8 || length > len(payload) {
			return stack.TransportEndpointID{}, 0, false
		}
		payload = payload[:length]
	}
	zeroUDP := protocol == udp.ProtocolNumber && packet[0]>>4 == 4 && binary.BigEndian.Uint16(payload[6:]) == 0
	if !zeroUDP && checksum.Checksum(payload, header.PseudoHeaderChecksum(protocol, src, dst, uint16(len(payload)))) != 0xffff {
		return stack.TransportEndpointID{}, 0, false
	}
	return stack.TransportEndpointID{LocalAddress: dst, LocalPort: binary.BigEndian.Uint16(payload[2:]), RemoteAddress: src, RemotePort: binary.BigEndian.Uint16(payload)}, protocol, true
}

func (e *ipEngine) close() {
	e.mu.Lock()
	e.closed = true
	tcpStates := e.tcp
	udpStates := e.udp
	e.tcp = make(map[stack.TransportEndpointID]*tcpForwardState)
	e.udp = make(map[stack.TransportEndpointID]*udpForwardState)
	e.pendingTCP = nil
	for _, state := range tcpStates {
		state.timer.Stop()
	}
	for _, state := range udpStates {
		state.timer.Stop()
	}
	e.mu.Unlock()
	for _, state := range tcpStates {
		state.cancel()
		_ = state.conn.Close()
	}
	for _, state := range udpStates {
		state.transport.closeWithError(ErrStackClosed)
		_ = state.transport.conn.Close()
	}
	e.link.Close()
	e.stack.Destroy()
	e.handlers.Wait()
	e.workers.Wait()
	for _, state := range tcpStates {
		<-state.stream.done
		state.queue.EventUnregister(&state.entry)
	}
	for _, state := range udpStates {
		<-state.transport.done
	}
}
