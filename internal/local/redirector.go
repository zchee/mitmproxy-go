// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"net"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Redirector manages one native redirector daemon and its packet transport.
// The daemon outlives frontend mode instances: stopping interception calls
// SetIntercept with an empty spec, while Close is reserved for final shutdown.
// No method may be called while holding the addon dispatch lock.
// Implementations serialize control and packet writes; one goroutine reads packets.
// macOS stream redirectors return an unsupported-operation error for packet I/O.
type Redirector interface {
	// Launch starts the daemon once, or returns success if it is already running.
	// ctx is the process-lifetime context, not an individual frontend's context.
	Launch(ctx context.Context) error

	// SetIntercept parses and normalizes spec, appending the own-PID exclusion
	// to nonempty rules. An empty spec disables interception without stopping
	// the daemon. The call honors cancellation and serializes with packet writes.
	SetIntercept(ctx context.Context, spec string) error

	// ReadPacket transfers ownership of a fresh message and its bytes to the caller.
	// It preserves each native message boundary and has only one concurrent reader.
	// Cancellation interrupts the call; terminal closure wraps net.ErrClosed.
	ReadPacket(ctx context.Context) (*PacketWithMeta, error)

	// WritePacket borrows packet and its bytes until return, writing one complete
	// native message. It honors cancellation; terminal closure wraps net.ErrClosed.
	WritePacket(ctx context.Context, packet *Packet) error

	// Close is idempotent final shutdown: it wakes I/O and joins owned goroutines.
	Close() error
}

// StreamRedirector exposes macOS per-flow streams without a packet netstack.
// Accepted transports belong to callers; closing one does not close the daemon.
type StreamRedirector interface {
	Redirector

	// AcceptTCP returns the stream after its NewFlow handshake and transfers
	// ownership of both the connection and metadata to the caller.
	AcceptTCP(ctx context.Context) (net.Conn, *TcpFlow, error)

	// AcceptUDP waits for the first UdpPacket to establish its fixed destination.
	// That packet remains available to the first ReadFrom on the returned tuple.
	// The caller owns the transport and metadata; datagram boundaries are preserved.
	AcceptUDP(ctx context.Context) (layer.PacketTransport, *UdpFlow, error)
}
