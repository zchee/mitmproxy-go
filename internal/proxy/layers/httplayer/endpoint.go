// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import "context"

// ClientEndpoint decodes requests from a client and encodes responses to it.
// It represents a connection, potentially carrying multiple exchanges.
//
// Exactly one goroutine owns Receive. Send may run concurrently with Receive
// and with sends for other streams; implementations serialize transport writes.
// Callers preserve event order within each stream. Neither method may be
// called while holding the dispatch lock. Cancellation of ctx must unblock
// the call without waiting for a peer to send or receive more bytes.
//
// Receive transfers ownership of the returned event and all mutable message
// and byte data to its caller; the endpoint must not mutate or reuse them.
// Send borrows its event until it returns and must neither mutate nor retain
// its mutable data afterwards. ReplayFlow is a shared identity, not owned
// message data, and may only be accessed under the dispatch lock.
//
// Stream protocol failures are RequestProtocolError events. A returned error
// describes a connection-level failure; io.EOF means no further events.
// No method fires addon hooks. Successful CONNECT and upgrade handovers are
// negotiated separately from this interface, preserving buffered bytes.
type ClientEndpoint interface {
	// Receive returns the next request event or a connection-level error.
	Receive(ctx context.Context) (RequestEvent, error)
	// Send writes one response event, respecting backpressure.
	Send(ctx context.Context, event ResponseEvent) error
}

// ServerEndpoint encodes requests to a server and decodes its responses.
// Its concurrency, ownership, cancellation and handover rules are those of
// ClientEndpoint, with the event directions reversed. Stream failures arrive
// as ResponseProtocolError events, not as connection-level returned errors.
type ServerEndpoint interface {
	// Receive returns the next response event or a connection-level error.
	Receive(ctx context.Context) (ResponseEvent, error)
	// Send writes one request event, respecting backpressure.
	Send(ctx context.Context, event RequestEvent) error
}
