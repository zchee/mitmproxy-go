// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type tlsConn struct {
	*tls.Conn
	raw layer.Conn

	// srv is the server the handshake was negotiated for, when this side
	// of the connection is a server upgrade; it lets a repeated setup for
	// the same server recognize the transport as already negotiated.
	srv *connection.Server

	// logger, when set, reports post-handshake record errors the way
	// upstream logs `TLS Error: ...` for a failed SSL read
	// (py:mitmproxy/proxy/layers/tls.py:408-429).
	logger *slog.Logger
}

// Read reports a fatal post-handshake record error in the log before
// returning it; the reader treats the error as the direction's close, per
// the layer package rules. A clean close_notify is an EOF, and the
// deadline and closed-connection errors of an interrupted relay are the
// interrupt's, not the peer's.
func (c *tlsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil && c.logger != nil &&
		!errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
		c.logger.Warn("TLS Error: " + err.Error())
	}
	return n, err
}

// CloseWrite sends TLS close_notify and half-closes the underlying transport.
func (c *tlsConn) CloseWrite() error {
	return errors.Join(c.Conn.CloseWrite(), c.raw.CloseWrite())
}
