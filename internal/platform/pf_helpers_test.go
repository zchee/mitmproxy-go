// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package platform

import (
	"net/netip"

	"github.com/zchee/mitmproxy-go/connection"
)

func pfStateLookup(peer netip.AddrPort, output []byte) (connection.Address, error) {
	return pfStateLookupForLocal(peer, netip.AddrPort{}, output)
}
