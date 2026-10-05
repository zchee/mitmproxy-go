// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"crypto/tls"
	"errors"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type tlsConn struct {
	*tls.Conn
	raw layer.Conn
}

func (c *tlsConn) CloseWrite() error {
	return errors.Join(c.Conn.CloseWrite(), c.raw.CloseWrite())
}
