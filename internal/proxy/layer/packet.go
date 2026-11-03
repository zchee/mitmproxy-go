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

// ErrPacketOverflow reports rejected packets or tuple admission at a size or queue bound.
// Shared UDP listeners silently drop newest datagrams at queue pressure instead.
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
// Admission never blocks the listener reader. Shared UDP listeners silently drop
// the newest datagram at either queue bound without retiring live tuples, and
// refuse unknown peers when aggregate capacity is unavailable. Oversized
// datagrams and full new-tuple accept queues still report ErrPacketOverflow.
// Writes borrow bytes only until return.
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
