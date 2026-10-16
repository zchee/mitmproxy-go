// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import "github.com/zchee/mitmproxy-go/internal/proxy/packettest"

type queuedDNSPeer struct{ *packettest.Transport }

func (p queuedDNSPeer) Read(data []byte) (int, error) {
	n, _, err := p.ReadFrom(data)
	return n, err
}

func (p queuedDNSPeer) Write(data []byte) (int, error) { return p.WriteTo(data, nil) }
