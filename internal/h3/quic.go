// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// The caller owns the packet socket and closes it after the transport. A socket
// belongs to exactly one transport, which owns its packet reads and writes.
type quicTransport struct {
	transport quic.Transport
}

func newQUICTransport(socket net.PacketConn) *quicTransport {
	return &quicTransport{transport: quic.Transport{Conn: socket}}
}

func (t *quicTransport) listen(tlsConfig *tls.Config, config *quic.Config) (*quicListener, error) {
	listener, err := t.transport.Listen(tlsConfig, config)
	if err != nil {
		return nil, err
	}
	return &quicListener{listener: listener}, nil
}

func (t *quicTransport) dial(ctx context.Context, address net.Addr, tlsConfig *tls.Config, config *quic.Config) (*quicConnection, error) {
	conn, err := t.transport.Dial(ctx, address, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	return &quicConnection{conn: conn}, nil
}

func (t *quicTransport) close() error { return t.transport.Close() }

type quicListener struct {
	listener *quic.Listener
}

func (l *quicListener) accept(ctx context.Context) (*quicConnection, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &quicConnection{conn: conn}, nil
}

func (l *quicListener) close() error { return l.listener.Close() }

type quicConnection struct {
	conn *quic.Conn
}

func (c *quicConnection) openStream(ctx context.Context) (*quic.Stream, error) {
	return c.conn.OpenStreamSync(ctx)
}

func (c *quicConnection) acceptStream(ctx context.Context) (*quic.Stream, error) {
	return c.conn.AcceptStream(ctx)
}

func (c *quicConnection) openUniStream(ctx context.Context) (*quic.SendStream, error) {
	return c.conn.OpenUniStreamSync(ctx)
}

func (c *quicConnection) acceptUniStream(ctx context.Context) (*quic.ReceiveStream, error) {
	return c.conn.AcceptUniStream(ctx)
}

func (c *quicConnection) closeWithError(code uint64) error {
	// Diagnostics belong in the local log, never in a peer-visible close reason.
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), "")
}

// New copies cfg and constructs an endpoint without I/O. A nil connection or
// empty endpoint identity is rejected. The caller retains connection ownership.
func New(conn *quic.Conn, cfg Config) (*Endpoint, error) {
	if conn == nil || cfg.Descriptor.Identity == "" {
		return nil, errors.New("h3: invalid endpoint configuration")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Endpoint{
		conn: &quicConnection{conn: conn}, cfg: cfg, done: make(chan struct{}),
		started: make(chan struct{}), ready: make(chan struct{}), changed: make(chan struct{}),
		streams: make(map[uint64]*requestState), notifications: make(chan Event, 2*MaxConcurrentStreams),
		controlLock: make(chan struct{}, 1), receiveLock: make(chan struct{}, 1),
		peerGoAway: maxQUICVarint, peerHeaderLimit: MaxHeaderBytes,
	}, nil
}

type (
	requestStream     = quic.Stream
	incomingUniStream = quic.ReceiveStream
	outgoingUniStream = quic.SendStream
)

func (c *quicConnection) context() context.Context { return c.conn.Context() }

func requestWriteContext(stream *requestStream) context.Context { return stream.Context() }

func interruptCriticalStreams(incoming *incomingUniStream, outgoing *outgoingUniStream) {
	// A graceful drain must interrupt local I/O without emitting a reset on a
	// critical stream, which would abort the peer before queued response FINs.
	if incoming != nil {
		_ = incoming.SetReadDeadline(time.Unix(1, 0))
	}
	if outgoing != nil {
		_ = outgoing.SetWriteDeadline(time.Unix(1, 0))
	}
}

func cancelRequestStream(stream *requestStream, code ErrorCode) {
	stream.CancelRead(quic.StreamErrorCode(code))
	stream.CancelWrite(quic.StreamErrorCode(code))
}

func cancelIncomingUni(stream *incomingUniStream, code ErrorCode) {
	stream.CancelRead(quic.StreamErrorCode(code))
}

func cancelOutgoingUni(stream *outgoingUniStream, code ErrorCode) {
	stream.CancelWrite(quic.StreamErrorCode(code))
}

func streamTransportError(err error, id layer.StreamIdentity) error {
	if streamErr, ok := errors.AsType[*quic.StreamError](err); ok {
		return &StreamError{Identity: id, Code: ErrorCode(streamErr.ErrorCode), Message: streamErr.Error()}
	}
	return err
}

func connectionTransportError(err error) error {
	if appErr, ok := errors.AsType[*quic.ApplicationError](err); ok {
		if ErrorCode(appErr.ErrorCode) == ErrCodeNoError {
			return io.EOF
		}
		return connectionError(ErrorCode(appErr.ErrorCode), appErr.Error())
	}
	return err
}

// Track whether any byte was consumed so a partial QUIC integer is not mistaken
// for a clean HTTP message EOF. quicvarint supplies the actual integer codec.
type varintReader struct {
	reader io.Reader
	read   bool
}

func (r *varintReader) ReadByte() (byte, error) {
	var b [1]byte
	n, err := io.ReadFull(r.reader, b[:])
	r.read = r.read || n != 0
	return b[0], err
}

func readVarint(reader io.Reader) (uint64, error) {
	r := varintReader{reader: reader}
	value, err := quicvarint.Read(&r)
	if errors.Is(err, io.EOF) && r.read {
		err = io.ErrUnexpectedEOF
	}
	return value, err
}

func appendVarint(buffer []byte, value uint64) []byte { return quicvarint.Append(buffer, value) }
