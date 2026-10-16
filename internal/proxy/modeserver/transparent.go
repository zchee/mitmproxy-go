// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import "net"

type transparentConn struct {
	*net.TCPConn
	endpoint string
}

// GetExtraInfo exposes the original destination without changing the socket addresses.
func (c *transparentConn) GetExtraInfo(key string) (any, bool) {
	if key == "remote_endpoint" {
		return c.endpoint, true
	}
	return nil, false
}
