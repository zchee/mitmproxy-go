// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/device"
)

// TestSocketDemux certifies the internal packet demultiplexer. Its identifiers
// are absent on the parent; the real encrypted routing test supplies parent-red.
func TestSocketDemux(t *testing.T) {
	tests := map[string]struct {
		kind      uint32
		register  []int
		wantPeers []int
	}{
		"success: initiation offered to every peer": {kind: device.MessageInitiationType, wantPeers: []int{0, 1}},
		"success: response to server initiation":    {kind: device.MessageResponseType, register: []int{1}, wantPeers: []int{1}},
		"success: cookie reply by receiver":         {kind: device.MessageCookieReplyType, register: []int{1}, wantPeers: []int{1}},
		"success: data by receiver":                 {kind: device.MessageTransportType, register: []int{0}, wantPeers: []int{0}},
		"success: colliding indices":                {kind: device.MessageTransportType, register: []int{0, 1}, wantPeers: []int{0, 1}},
		"error: unknown receiver":                   {kind: device.MessageTransportType},
		"error: incoming response cannot register":  {kind: device.MessageResponseType},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			demux := newSocketDemux(nil, 2, slog.New(slog.DiscardHandler))
			for _, peer := range test.register {
				demux.register(demuxTestPacket(device.MessageInitiationType, 42, 0), peer)
			}
			packet := demuxTestPacket(test.kind, 73, 42)
			from := netip.MustParseAddrPort("127.0.0.1:51820")
			demux.dispatch(packet, from)
			var received []int
			for peer, queue := range demux.queues {
				select {
				case datagram := <-queue:
					received = append(received, peer)
					if diff := gocmp.Diff(packet, datagram.packet); diff != "" {
						t.Errorf("received datagram (-want +got):\n%s", diff)
					}
					if datagram.from != from {
						t.Error("demultiplexer changed the roaming endpoint")
					}
					packet[0] = 0
					if datagram.packet[0] == 0 {
						t.Error("demultiplexer retained the reusable socket buffer")
					}
					packet[0] = byte(test.kind)
				default:
				}
			}
			if diff := gocmp.Diff(test.wantPeers, received); diff != "" {
				t.Errorf("recipient peers (-want +got):\n%s", diff)
			}
			if len(test.register) == 0 && len(demux.indices) != 0 {
				t.Error("inbound packet registered an unauthenticated index")
			}
		})
	}
}

// TestSocketDemuxIndexExpiry uses an injected clock, not a timing wait.
func TestSocketDemuxIndexExpiry(t *testing.T) {
	tests := map[string]struct{ advance time.Duration }{
		"success: obsolete registration pruned": {advance: 2 * device.RejectAfterTime},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clock := time.Unix(0, 0)
			demux := newSocketDemux(nil, 2, slog.New(slog.DiscardHandler))
			demux.now = func() time.Time { return clock }
			demux.register(demuxTestPacket(device.MessageResponseType, 42, 0), 0)
			clock = clock.Add(test.advance)
			demux.dispatch(demuxTestPacket(device.MessageTransportType, 0, 42), netip.AddrPort{})
			if len(demux.queues[0]) != 0 {
				t.Error("expired receiver index still admitted a datagram")
			}
			demux.register(demuxTestPacket(device.MessageResponseType, 73, 0), 1)
			if _, stale := demux.indices[42]; stale || len(demux.indices) != 1 {
				t.Error("new handshake retained an obsolete receiver index")
			}
		})
	}
}

func TestSocketDemuxBounds(t *testing.T) {
	tests := map[string]struct{ packet []byte }{
		"error: missing header":       {},
		"error: truncated initiation": {packet: demuxTestPacket(device.MessageInitiationType, 0, 0)[:20]},
		"error: unknown message":      {packet: demuxTestPacket(99, 0, 0)},
		"error: queue overflow":       {packet: demuxTestPacket(device.MessageInitiationType, 0, 0)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			demux := newSocketDemux(nil, 2, slog.New(slog.DiscardHandler))
			for range peerPacketQueueSize + 1 {
				demux.dispatch(test.packet, netip.AddrPort{})
			}
			for _, queue := range demux.queues {
				if len(queue) > peerPacketQueueSize {
					t.Error("encrypted datagram queue exceeded its bound")
				}
			}
			if demux.dropped.Load() == 0 {
				t.Error("invalid or overflowing datagram was not dropped")
			}
		})
	}
}

func demuxTestPacket(kind, sender, receiver uint32) []byte {
	size := map[uint32]int{
		device.MessageInitiationType:  device.MessageInitiationSize,
		device.MessageResponseType:    device.MessageResponseSize,
		device.MessageCookieReplyType: device.MessageCookieReplySize,
		device.MessageTransportType:   device.MessageTransportSize,
	}[kind]
	packet := make([]byte, max(size, 12))
	binary.LittleEndian.PutUint32(packet, kind)
	binary.LittleEndian.PutUint32(packet[4:], sender)
	if kind == device.MessageResponseType {
		binary.LittleEndian.PutUint32(packet[8:], receiver)
	} else if kind != device.MessageInitiationType {
		binary.LittleEndian.PutUint32(packet[4:], receiver)
	}
	return packet
}
