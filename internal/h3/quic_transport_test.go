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
