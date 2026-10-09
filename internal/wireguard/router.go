// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

const peerPacketQueueSize = 64

// packetRouter keeps authenticated source ownership separate from each engine's
// default AllowedIPs. Old addresses remain learned when a peer changes address.
type packetRouter struct {
	mu      sync.Mutex
	sources map[netip.Addr]int
	queues  []chan []byte
	logger  *slog.Logger
	dropped atomic.Uint64
}

func newPacketRouter(peers int, logger *slog.Logger) *packetRouter {
	router := &packetRouter{sources: make(map[netip.Addr]int), queues: make([]chan []byte, peers), logger: logger}
	for i := range peers {
		router.queues[i] = make(chan []byte, peerPacketQueueSize)
	}
	return router
}

func (r *packetRouter) run(ctx context.Context, stack *netstack.Stack, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-stack.Outbound():
			if !ok {
				cancel()
				return
			}
			_, destination, valid := packetAddresses(packet)
			if !valid {
				r.drop()
				continue
			}
			r.mu.Lock()
			peer := r.sources[destination] // Missing addresses use the first configured peer.
			r.mu.Unlock()
			select {
			case r.queues[peer] <- packet:
			case <-ctx.Done():
				return
			default:
				r.drop()
			}
		}
	}
}

func (r *packetRouter) drop() {
	count := r.dropped.Add(1)
	if count&(count-1) == 0 {
		r.logger.Warn("Dropping outgoing WireGuard packet, peer queue is full or packet is invalid.", "dropped", count)
	}
}

func packetAddresses(packet []byte) (source, destination netip.Addr, valid bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ip := header.IPv4(packet)
		if !ip.IsValid(len(packet)) {
			return source, destination, false
		}
		return netip.AddrFrom4(ip.SourceAddress().As4()), netip.AddrFrom4(ip.DestinationAddress().As4()), true
	case header.IPv6Version:
		ip := header.IPv6(packet)
		if !ip.IsValid(len(packet)) {
			return source, destination, false
		}
		return netip.AddrFrom16(ip.SourceAddress().As16()), netip.AddrFrom16(ip.DestinationAddress().As16()), true
	default:
		return source, destination, false
	}
}
