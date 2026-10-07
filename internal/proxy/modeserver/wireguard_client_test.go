// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// NetTUN hides its loopback policy. This adapter uses the same public packet
// and socket APIs with explicit acceptance of replies from the tunnel host.
type modeClientTUN struct {
	stack  *stack.Stack
	link   *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	events chan tun.Event
	once   sync.Once
}

type modeClientNetwork struct{ stack *stack.Stack }

func modeClientStack(parent context.Context, address netip.Addr) (*modeClientTUN, *modeClientNetwork, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(256, 1420, "")
	fail := func(err tcpip.Error) (*modeClientTUN, *modeClientNetwork, error) {
		link.Close()
		s.Destroy()
		return nil, nil, errors.New(err.String())
	}
	if err := s.CreateNIC(1, link); err != nil {
		return fail(err)
	}
	protocol := header.IPv4ProtocolNumber
	if address.Is6() {
		protocol = header.IPv6ProtocolNumber
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddrFromSlice(address.AsSlice()).WithPrefix()}, stack.AddressProperties{}); err != nil {
		return fail(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(parent)
	t := &modeClientTUN{stack: s, link: link, ctx: ctx, cancel: cancel, events: make(chan tun.Event, 1)}
	t.events <- tun.EventUp
	return t, &modeClientNetwork{stack: s}, nil
}

// File is nil because the test device has no kernel descriptor.
func (*modeClientTUN) File() *os.File { return nil }

// MTU is the packet size used by both tunnel endpoints.
func (*modeClientTUN) MTU() (int, error) { return 1420, nil }

// Name identifies this in-memory client packet device.
func (*modeClientTUN) Name() (string, error) { return "mode-client", nil }

// BatchSize keeps packet reads independently bounded.
func (*modeClientTUN) BatchSize() int { return 1 }

// Events reports the initialized packet device to the real WireGuard engine.
func (t *modeClientTUN) Events() <-chan tun.Event { return t.events }

// Read returns one real IP packet emitted by the client protocol stack.
func (t *modeClientTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	packet := t.link.ReadContext(t.ctx)
	if packet == nil {
		return 0, net.ErrClosed
	}
	defer packet.DecRef()
	data := packet.ToBuffer()
	defer data.Release()
	bytes := data.Flatten()
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) || len(bytes) > len(bufs[0])-offset {
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(bufs[0][offset:], bytes)
	return 1, nil
}

// Write injects decrypted peer packets without modifying their addresses.
func (t *modeClientTUN) Write(bufs [][]byte, offset int) (int, error) {
	for n, data := range bufs {
		if t.ctx.Err() != nil {
			return n, net.ErrClosed
		}
		if offset < 0 || offset >= len(data) {
			return n, io.ErrShortBuffer
		}
		data = data[offset:]
		protocol := header.IPv4ProtocolNumber
		if data[0]>>4 == 6 {
			protocol = header.IPv6ProtocolNumber
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		t.link.InjectInbound(protocol, packet)
		packet.DecRef()
	}
	return len(bufs), nil
}

// Close releases the protocol stack and wakes the engine's blocked reader.
func (t *modeClientTUN) Close() error {
	t.once.Do(func() { t.cancel(); t.link.Close(); t.stack.Destroy(); close(t.events) })
	return nil
}

func (n *modeClientNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("test client supports TCP dialing only")
	}
	destination, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	protocol := header.IPv4ProtocolNumber
	if destination.Addr().Is6() {
		protocol = header.IPv6ProtocolNumber
	}
	return gonet.DialContextTCP(ctx, n.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(destination.Addr().AsSlice()), Port: destination.Port()}, protocol)
}

func (n *modeClientNetwork) DialUDPAddrPort(local, destination netip.AddrPort) (*gonet.UDPConn, error) {
	var localAddress *tcpip.FullAddress
	if local.IsValid() {
		localAddress = &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(local.Addr().AsSlice()), Port: local.Port()}
	}
	protocol := header.IPv4ProtocolNumber
	if destination.Addr().Is6() {
		protocol = header.IPv6ProtocolNumber
	}
	return gonet.DialUDP(n.stack, localAddress, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(destination.Addr().AsSlice()), Port: destination.Port()}, protocol)
}
