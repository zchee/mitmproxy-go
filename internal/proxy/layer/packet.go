// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import (
	"context"
	"errors"
	"net"
)

const (
	// MaxUDPPacketBytes bounds a portable UDP payload, excluding IP/UDP headers.
	MaxUDPPacketBytes = 65507
	// PacketQueueCapacity bounds queued datagrams for one fixed tuple.
	PacketQueueCapacity = 64
	// PacketQueueBytes bounds queued payload bytes for one fixed tuple.
	PacketQueueBytes = 1 << 20
	// ListenerPacketQueueCapacity bounds datagrams queued across a listener.
	ListenerPacketQueueCapacity = 4096
	// ListenerPacketQueueBytes bounds queued payload bytes across a listener.
	ListenerPacketQueueBytes = 64 << 20
)

// ErrPacketOverflow reports either packet-count or payload-byte queue overflow.
// Overflow must be surfaced to the flow owner rather than silently dropping data.
var ErrPacketOverflow = errors.New("proxy: packet queue limit exceeded")

// PacketTransport is a virtual packet connection for a fixed client/server tuple.
// ReadFrom and WriteTo preserve each datagram, including empty datagrams. Read
// truncation discards the remaining bytes of that packet, as net.PacketConn does.
// The transport owns independent read/write deadlines. Context cancellation,
// Close or expiry wake blocked operations with errors wrapping net.ErrClosed
// (and the context error for cancellation), release queued packets and evict only
// this tuple; they never close the shared listener or another tuple. Reusing an
// evicted tuple constructs a new transport and flow, without migration.
// Both packet-count and payload-byte bounds above apply per tuple and listener.
// Admission never blocks the listener reader; rejected input surfaces
// ErrPacketOverflow to the owning flow. Writes borrow bytes only until return.
// Packet transports do not implement TCP half-close semantics.
type PacketTransport interface {
	net.PacketConn
	// Context is cancelled when this tuple's transport ends.
	Context() context.Context
	// RemoteAddr is the fixed peer to which this tuple sends datagrams.
	RemoteAddr() net.Addr
}

// PacketRecorder preserves datagram boundaries while sniffing and replaying.
// It shares PacketTransport queue bounds, never the byte-stream Recorder.
// One owner reads or peeks at a time; deadline/Close operations may be concurrent.
type PacketRecorder interface {
	PacketTransport
	// PeekPacket returns the next whole packet without consuming it. Its bytes
	// are borrowed until the next read/peek or StopRecording; copy to retain.
	// An empty payload with nil error is a valid datagram, never transport EOF.
	PeekPacket() ([]byte, net.Addr, error)
	// BufferedPackets counts complete packets available without socket I/O.
	BufferedPackets() int
	// StopRecording rewinds consumed packets exactly once in original order,
	// followed by peeked packets then live input. Repeated calls are no-ops.
	StopRecording()
}
