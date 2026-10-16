// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package packettest provides bounded, queued packet peers for protocol fixtures.
// Production code must not import this package.
package packettest

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type packetPair struct {
	mu      sync.Mutex
	changed chan struct{}
}

// Transport is one fixed-peer, packet-preserving end of a queued pair.
// It has no delivery worker: a successful write only queues a cloned datagram,
// never a protocol response. Close joins its context-cancellation callback.
// Returned address values are copies, so callers cannot change its identity.
type Transport struct {
	pair          *packetPair
	peer          *Transport
	local         netip.AddrPort
	ctx           context.Context
	parent        context.Context
	cancel        context.CancelCauseFunc
	stopParent    func() bool
	parentDone    chan struct{}
	joinOnce      sync.Once
	closed        error
	packets       [layer.PacketQueueCapacity][]byte
	head          int
	count         int
	bytes         int
	readDeadline  time.Time
	writeDeadline time.Time
}

var _ layer.PacketTransport = (*Transport)(nil)

// NewPair returns two queued UDP peers with the given fixed local identities.
// Invalid, identical or port-zero addresses are rejected. Canceling ctx closes
// both peers; closing one peer wakes operations without closing the other peer.
// The caller owns both endpoints and must close them to join cancellation work.
func NewPair(ctx context.Context, left, right netip.AddrPort) (*Transport, *Transport, error) {
	if !left.IsValid() || !right.IsValid() || left.Port() == 0 || right.Port() == 0 || left == right {
		return nil, nil, errors.New("packettest: pair requires distinct valid UDP identities with nonzero ports")
	}
	pair := &packetPair{changed: make(chan struct{})}
	a := &Transport{pair: pair, local: left, parentDone: make(chan struct{})}
	b := &Transport{pair: pair, local: right, parentDone: make(chan struct{})}
	a.peer, b.peer = b, a
	for _, p := range []*Transport{a, b} {
		p.parent = ctx
		p.ctx, p.cancel = context.WithCancelCause(context.WithoutCancel(ctx))
		p.stopParent = context.AfterFunc(ctx, func() {
			defer close(p.parentDone)
			p.pair.mu.Lock()
			p.closeLocked(context.Cause(ctx))
			p.pair.mu.Unlock()
		})
	}
	return a, b, nil
}

// Context ends when this endpoint closes, overflows or its parent is canceled.
func (p *Transport) Context() context.Context { return p.ctx }

// LocalAddr returns this endpoint's fixed local UDP identity.
func (p *Transport) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(p.local) }

// RemoteAddr returns the other endpoint's fixed UDP identity.
func (p *Transport) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(p.peer.local) }

func (p *Transport) notifyLocked() {
	close(p.pair.changed)
	p.pair.changed = make(chan struct{})
}

func (p *Transport) closeLocked(cause error) {
	if p.closed != nil {
		return
	}
	p.closed = errors.Join(net.ErrClosed, cause)
	clear(p.packets[:])
	p.head, p.count, p.bytes = 0, 0, 0
	p.cancel(cause)
	p.notifyLocked()
}

// Close releases queued input, wakes blocked operations, and joins any running
// parent-cancellation callback. Repeated and concurrent calls are harmless.
func (p *Transport) Close() error {
	p.pair.mu.Lock()
	p.closeLocked(context.Cause(p.parent))
	p.pair.mu.Unlock()
	p.joinOnce.Do(func() {
		if !p.stopParent() {
			<-p.parentDone
		}
	})
	return nil
}

// ReadFrom consumes exactly one datagram, including empty datagrams. If data is
// too short, the packet's unreturned bytes are discarded rather than replayed.
func (p *Transport) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		p.pair.mu.Lock()
		if p.closed != nil {
			err := p.closed
			p.pair.mu.Unlock()
			return 0, nil, err
		}
		deadline := p.readDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			p.pair.mu.Unlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		if p.count > 0 {
			packet := p.packets[p.head]
			p.packets[p.head] = nil
			p.head = (p.head + 1) % len(p.packets)
			p.count--
			p.bytes -= len(packet)
			p.pair.mu.Unlock()
			return copy(data, packet), p.RemoteAddr(), nil
		}
		changed := p.pair.changed
		p.pair.mu.Unlock()
		if deadline.IsZero() {
			<-changed
		} else {
			timer := time.NewTimer(time.Until(deadline))
			select {
			case <-changed:
			case <-timer.C:
			}
			timer.Stop()
		}
	}
}

// WriteTo clones and queues one datagram for the fixed peer without waiting for
// a reader. A different destination is rejected. Oversized packets or queue
// count/byte overflow close the receiving endpoint with layer.ErrPacketOverflow.
func (p *Transport) WriteTo(data []byte, addr net.Addr) (int, error) {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	if p.closed != nil {
		return 0, p.closed
	}
	if p.peer.closed != nil {
		return 0, p.peer.closed
	}
	if !p.writeDeadline.IsZero() && !time.Now().Before(p.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if addr != nil && (addr.Network() != "udp" || addr.String() != p.RemoteAddr().String()) {
		return 0, errors.New("packettest: destination differs from fixed peer")
	}
	peer := p.peer
	if len(data) > layer.MaxUDPPacketBytes || peer.count == len(peer.packets) || len(data) > layer.PacketQueueBytes-peer.bytes {
		peer.closeLocked(layer.ErrPacketOverflow)
		return 0, layer.ErrPacketOverflow
	}
	peer.packets[(peer.head+peer.count)%len(peer.packets)] = bytes.Clone(data)
	peer.count++
	peer.bytes += len(data)
	p.notifyLocked()
	return len(data), nil
}

// SetDeadline replaces both deadlines and wakes blocked reads to recheck them.
func (p *Transport) SetDeadline(deadline time.Time) error {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	if p.closed != nil {
		return p.closed
	}
	p.readDeadline, p.writeDeadline = deadline, deadline
	p.notifyLocked()
	return nil
}

// SetReadDeadline replaces the read deadline and wakes blocked reads.
func (p *Transport) SetReadDeadline(deadline time.Time) error {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	if p.closed != nil {
		return p.closed
	}
	p.readDeadline = deadline
	p.notifyLocked()
	return nil
}

// SetWriteDeadline replaces the deadline checked by subsequent writes.
func (p *Transport) SetWriteDeadline(deadline time.Time) error {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	if p.closed != nil {
		return p.closed
	}
	p.writeDeadline = deadline
	p.notifyLocked()
	return nil
}
