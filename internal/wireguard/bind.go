// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// socketBind adapts an operator-bound UDP listener without rebinding all hosts.
// One lifetime is supported: closing an opened bind consumes the supplied socket.
type socketBind struct {
	mu       sync.Mutex
	socket   net.PacketConn
	cancel   context.CancelFunc
	logger   *slog.Logger
	opened   bool
	closed   bool
	closeErr error
}

var _ conn.Bind = (*socketBind)(nil)

// Open exposes the existing listener at its bound port, without changing its host.
func (b *socketBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, 0, net.ErrClosed
	}
	if b.opened {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.socket == nil {
		return nil, 0, errors.New("WireGuard requires a UDP socket")
	}
	address, ok := b.socket.LocalAddr().(*net.UDPAddr)
	if !ok || address.Port <= 0 || address.Port > 65535 {
		return nil, 0, errors.New("WireGuard requires a bound UDP socket")
	}
	actualPort := uint16(address.Port)
	if port != 0 && port != actualPort {
		return nil, 0, errors.New("WireGuard socket is bound to a different port")
	}
	b.opened = true
	return []conn.ReceiveFunc{b.receive}, actualPort, nil
}

func (b *socketBind) receive(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
	if len(packets) != 1 || len(sizes) < 1 || len(endpoints) < 1 {
		return 0, errors.New("WireGuard socket bind requires one receive buffer")
	}
	n, from, err := b.socket.ReadFrom(packets[0])
	if err != nil {
		if b.cancel != nil {
			b.cancel()
		}
		return 0, err
	}
	if n < 4 && b.logger != nil {
		b.logger.Error("Received invalid WireGuard packet.")
	}
	address, ok := from.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("WireGuard received a non-UDP endpoint")
	}
	peer := address.AddrPort()
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	sizes[0] = n
	endpoints[0] = &conn.StdNetEndpoint{AddrPort: peer}
	return 1, nil
}

// Close consumes an opened socket and interrupts every pending receive.
func (b *socketBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// NewDevice calls BindClose before Open, so retain the unopened socket.
	if !b.opened || b.closed {
		return b.closeErr
	}
	b.closed = true
	b.closeErr = b.socket.Close()
	return b.closeErr
}

// SetMark accepts the unused zero mark; packet-source mode configures no marks.
func (*socketBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("WireGuard packet marks are not supported")
	}
	return nil
}

// Send preserves each datagram and the supplied numeric peer endpoint.
func (b *socketBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	if len(packets) > b.BatchSize() || endpoint == nil {
		return errors.New("invalid WireGuard send batch or endpoint")
	}
	peer, err := netip.ParseAddrPort(endpoint.DstToString())
	if err != nil {
		return err
	}
	for _, packet := range packets {
		n, err := b.socket.WriteTo(packet, net.UDPAddrFromAddrPort(peer))
		if err != nil {
			return err
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ParseEndpoint uses WireGuard's standard endpoint representation for numeric IPs.
func (*socketBind) ParseEndpoint(text string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(text)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: address}, nil
}

// BatchSize is fixed at one because net.PacketConn reads individual datagrams.
func (*socketBind) BatchSize() int { return 1 }
