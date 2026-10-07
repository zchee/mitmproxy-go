// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Config is an immutable endpoint configuration, copied by New. Client selects
// the upstream-facing client role; false selects the client-facing server role.
// Inbound fields stay ordered and unnormalized, with optional RFC validation.
// PingKeepalive is the upstream inactivity interval; zero disables keepalive.
// Nil Clock and Logger select the wall clock and the default logger.
type Config struct {
	Descriptor             layer.EndpointDescriptor
	Client                 bool
	ValidateInboundHeaders bool
	Logger                 *slog.Logger
	PingKeepalive          time.Duration
	Clock                  layer.Clock
	// Upgrade seeds an HTTP/1 h2c request on stream 1 in server mode only.
	// The client preface and its first SETTINGS frame are still required.
	Upgrade *UpgradeRequest
}

// UpgradeRequest supplies the fully read HTTP/1 request that initiated h2c.
// New validates and copies its fields before the endpoint performs any I/O.
// Receive delivers its Headers first with EndStream true only for an empty Body.
// ReceiveStream delivers Body in ChunkSize-capacity chunks, with EndStream only
// on the final chunk and ordinary original-byte receipts. An empty Body yields
// no DATA event.
// Stream 1 is half-closed remotely and may receive a response through Send.
// Body must not exceed InitialStreamWindow, preserving the receive budget.
// Settings is the decoded HTTP2-Settings payload, without a frame header;
// unknown parameters are ignored and the 101 response implicitly acknowledges it.
// Subsequent client SETTINGS frames update these limits and are acknowledged.
// Headers contains the caller-converted request pseudo-headers and fields.
type UpgradeRequest struct {
	Settings []byte
	Headers  []hpack.HeaderField
	Body     []byte
}

// EventKind identifies an ordered HTTP/2 protocol event.
type EventKind uint8

const (
	// Headers carries a request or final response header list.
	Headers EventKind = iota + 1
	// Informational carries a response before the final response headers.
	Informational
	// Data carries a receive chunk or borrowed outgoing bytes.
	Data
	// Trailers carries terminal header fields after the message body.
	Trailers
	// Reset reports a stream cancellation and its HTTP/2 error code.
	Reset
	// GoAway reports connection shutdown and its last accepted stream.
	GoAway
)

// Event contains raw ordered header fields or an ownership-transferred DATA
// chunk. EndStream belongs to the carrying Headers, Data or Trailers event.
// Received Data has ChunkSize capacity and stays valid until Receipt settles;
// pass it directly to the other endpoint's Send, then complete the receipt only
// after all transformed output is socket-written or deliberately dropped.
// Receipt counts original flow-controlled bytes including padding, not output.
// Cancellation invalidates receipts without crediting a closed stream.
type Event struct {
	Kind         EventKind
	Identity     layer.StreamIdentity
	Headers      []hpack.HeaderField
	Data         []byte
	Receipt      layer.ConsumptionReceipt
	EndStream    bool
	Code         http2.ErrCode
	LastStreamID uint32
	Err          error
}

// ErrDraining rejects OpenStream after GOAWAY before any request bytes are written.
// Already accepted streams may continue until the endpoint finishes draining.
var ErrDraining = errors.New("h2: connection is draining")

// StreamError is a typed rejection of an unknown, closed or foreign stream.
type StreamError struct {
	Identity layer.StreamIdentity
	Code     http2.ErrCode
	Message  string
}

// Error returns the stream diagnostic.
func (e *StreamError) Error() string { return e.Message }

// Unwrap makes ended streams match the closed-transport sentinel.
func (e *StreamError) Unwrap() error { return io.ErrClosedPipe }

type resetError struct {
	cause      error
	peer       string
	code       http2.ErrCode
	connection bool
	debug      string
}

func (e *resetError) Error() string {
	if e.connection {
		return "connection closed by " + e.peer + ": " + e.debug
	}
	name := e.code.String()
	if e.code > http2.ErrCodeHTTP11Required {
		name = strconv.FormatUint(uint64(e.code), 10)
	}
	return "stream reset by " + e.peer + " (" + name + ")"
}

func (e *resetError) Unwrap() error { return e.cause }

// IsConnectionClosed reports whether err carries a connection-level peer failure.
// It follows wrapped causes without matching diagnostic text.
func IsConnectionClosed(err error) bool {
	var reset *resetError
	return errors.As(err, &reset) && reset != nil && reset.connection
}

type result struct {
	event Event
	err   error
}

type request struct {
	ctx    context.Context
	kind   requestKind
	event  Event
	id     layer.StreamIdentity
	code   http2.ErrCode
	debug  []byte
	result chan result
	done   <-chan struct{}
}

type requestKind uint8

const (
	receive requestKind = iota
	receiveStream
	openStream
	send
	cancelStream
	shutdown
	waitSendCredit
	streamDone
	streamFailed
)

func newRequest(ctx context.Context, kind requestKind) *request {
	return &request{ctx: ctx, kind: kind, result: make(chan result, 1)}
}

func (r *request) complete(event Event, err error) {
	r.result <- result{event: event, err: err}
}

func streamError(id layer.StreamIdentity, code http2.ErrCode, message string) error {
	return &StreamError{Identity: id, Code: code, Message: message}
}

func terminalError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return errors.Join(ctx.Err(), err)
	}
	return err
}
