// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"crypto/tls"
	"net"

	quic "github.com/quic-go/quic-go"
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
