// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"crypto/tls"
	"errors"

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
}

func (c *tlsConn) CloseWrite() error {
	return errors.Join(c.Conn.CloseWrite(), c.raw.CloseWrite())
}
