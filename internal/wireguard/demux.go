// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

type encryptedDatagram struct {
	packet []byte
	from   netip.AddrPort
}

type indexPeer struct {
	peer    int
	expires time.Time
}

// socketDemux shares the bound listener without sharing engine peer tables.
// Indices come only from locally generated handshakes; inbound bytes cannot
// register a peer. Authentication remains entirely inside wireguard-go.
type socketDemux struct {
	mu      sync.Mutex
	indices map[uint32][]indexPeer
	queues  []chan encryptedDatagram
	socket  net.PacketConn
	logger  *slog.Logger
	now     func() time.Time
	dropped atomic.Uint64
}

func newSocketDemux(socket net.PacketConn, peers int, logger *slog.Logger) *socketDemux {
	demux := &socketDemux{indices: make(map[uint32][]indexPeer), queues: make([]chan encryptedDatagram, peers), socket: socket, logger: logger, now: time.Now}
	for i := range peers {
		demux.queues[i] = make(chan encryptedDatagram, peerPacketQueueSize)
	}
	return demux
}

func (d *socketDemux) run(ctx context.Context, cancel context.CancelFunc) {
	buffer := make([]byte, device.MaxMessageSize)
	for {
		n, from, err := d.socket.ReadFrom(buffer)
		if err != nil {
			cancel()
			return
		}
		if ctx.Err() != nil {
			return
		}
		address, ok := from.(*net.UDPAddr)
		if !ok {
			d.drop()
			continue
		}
		peer := address.AddrPort()
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		d.dispatch(buffer[:n], peer)
	}
}

func (d *socketDemux) register(packet []byte, peer int) {
	if len(packet) < 8 {
		return
	}
	kind := binary.LittleEndian.Uint32(packet)
	if kind != device.MessageInitiationType && kind != device.MessageResponseType {
		return
	}
	index := binary.LittleEndian.Uint32(packet[4:])
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	// Keep registrations beyond the engine's maximum key lifetime, but do not
	// retain every obsolete index for the listener's entire lifetime.
	for old, peers := range d.indices {
		peers = slices.DeleteFunc(peers, func(p indexPeer) bool { return !now.Before(p.expires) })
		if len(peers) == 0 {
			delete(d.indices, old)
		} else {
			d.indices[old] = peers
		}
	}
	expires := now.Add(2 * device.RejectAfterTime)
	for i, existing := range d.indices[index] {
		if existing.peer == peer {
			d.indices[index][i].expires = expires
			return
		}
	}
	// Independent engines may choose the same random index. Offer a collision
	// to both engines rather than dropping the authenticated owner's packet.
	d.indices[index] = append(d.indices[index], indexPeer{peer: peer, expires: expires})
}

func (d *socketDemux) dispatch(packet []byte, from netip.AddrPort) {
	if len(packet) < 8 {
		d.drop()
		return
	}
	kind := binary.LittleEndian.Uint32(packet)
	var index uint32
	switch kind {
	case device.MessageInitiationType:
		if len(packet) != device.MessageInitiationSize {
			d.drop()
			return
		}
	case device.MessageResponseType:
		if len(packet) != device.MessageResponseSize {
			d.drop()
			return
		}
		index = binary.LittleEndian.Uint32(packet[8:])
	case device.MessageCookieReplyType:
		if len(packet) != device.MessageCookieReplySize {
			d.drop()
			return
		}
		index = binary.LittleEndian.Uint32(packet[4:])
	case device.MessageTransportType:
		if len(packet) < device.MessageTransportSize {
			d.drop()
			return
		}
		index = binary.LittleEndian.Uint32(packet[4:])
	default:
		d.drop()
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if kind != device.MessageInitiationType && len(d.indices[index]) == 0 {
		d.drop()
		return
	}
	// One immutable copy can be shared by handshake recipients. Each bind
	// copies into the engine's owned receive buffer before authentication.
	datagram := encryptedDatagram{packet: bytes.Clone(packet), from: from}
	if kind == device.MessageInitiationType {
		for _, queue := range d.queues {
			select {
			case queue <- datagram:
			default:
				d.drop()
			}
		}
		return
	}
	now := d.now()
	for _, peer := range d.indices[index] {
		if !now.Before(peer.expires) {
			continue
		}
		select {
		case d.queues[peer.peer] <- datagram:
		default:
			d.drop()
		}
	}
}

func (d *socketDemux) drop() {
	count := d.dropped.Add(1)
	if count&(count-1) == 0 {
		d.logger.Debug("Dropping invalid, unknown-peer or full-queue WireGuard datagram.", "dropped", count)
	}
}
