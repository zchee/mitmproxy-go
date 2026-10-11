// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"container/list"
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

const (
	peerPacketQueueSize = 64
	maxLearnedSources   = 4096
)

type sourceRoute struct {
	source netip.Addr
	peer   int
}

// packetRouter keeps authenticated source ownership separate from each engine's
// default AllowedIPs. Learned addresses share one bounded LRU across all peers.
type packetRouter struct {
	mu      sync.Mutex
	sources map[netip.Addr]*list.Element
	recency list.List
	queues  []chan []byte
	logger  *slog.Logger
	dropped atomic.Uint64
}

func newPacketRouter(peers int, logger *slog.Logger) *packetRouter {
	router := &packetRouter{sources: make(map[netip.Addr]*list.Element), queues: make([]chan []byte, peers), logger: logger}
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
			peer := r.peerFor(destination)
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

func (r *packetRouter) peerFor(destination netip.Addr) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry := r.sources[destination]; entry != nil {
		r.recency.MoveToFront(entry)
		return entry.Value.(*sourceRoute).peer
	}
	// Missing or evicted sources use peer 0 until a successfully admitted
	// authenticated packet relearns their sender; lookup does not learn routes.
	return 0
}

// learnLocked publishes ownership only after admission, with r.mu held so an
// immediately generated reply cannot observe a missing or previous owner.
func (r *packetRouter) learnLocked(source netip.Addr, peer int) {
	if entry := r.sources[source]; entry != nil {
		entry.Value.(*sourceRoute).peer = peer
		r.recency.MoveToFront(entry)
		return
	}
	if len(r.sources) == maxLearnedSources {
		entry := r.recency.Back()
		route := entry.Value.(*sourceRoute)
		delete(r.sources, route.source)
		route.source, route.peer = source, peer
		r.recency.MoveToFront(entry)
		r.sources[source] = entry
		return
	}
	r.sources[source] = r.recency.PushFront(&sourceRoute{source: source, peer: peer})
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
