// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// ServerSetup returns the setup callback that upgrades an open server
// transport to TLS, for use as [layer.OpenOptions].Setup when the server
// is to be reached over TLS (an HTTPS origin, or an HTTPS upstream
// proxy). It performs the same upgrade the server TLS layer applies to
// the connections its child opens: it marks the connection's TLS intent,
// fires tls_start_server and uses the configuration exactly as the
// handlers left it, performs the handshake, publishes the negotiated
// connection fields, and fires tls_established_server, or
// tls_failed_server with the explanatory diagnostic on failure. A
// handshake for a server other than the context's fires its hooks with a
// context whose server is rebound to that target.
//
// The callback is idempotent for a transport it already negotiated: asked
// to set up TLS for the same server again, it returns the established
// connection unchanged. Asked for a different server over an established
// TLS transport, it nests a new session inside the outer one, as a
// CONNECT through an HTTPS upstream proxy requires.
func ServerSetup(c *layer.Context) func(ctx context.Context, conn layer.Conn, srv *connection.Server) (layer.Conn, error) {
	pool := &serverTLSPool{c: c}
	return func(ctx context.Context, conn layer.Conn, srv *connection.Server) (layer.Conn, error) {
		if established, ok := conn.(*tlsConn); ok && established.srv == srv {
			return conn, nil
		}
		if err := pool.markTLS(ctx, srv); err != nil {
			return nil, err
		}
		return pool.setup(ctx, conn, srv)
	}
}
