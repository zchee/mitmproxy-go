// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"net/netip"
	"testing"
)

func FuzzInjectedPacket(f *testing.F) {
	f.Add(echoPacket(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.42")))
	f.Add(echoPacket(netip.MustParseAddr("ca:fe:ca:fe:ca:fe:0:1"), netip.MustParseAddr("ca:fe:ca:fe:ca:fe:0:2")))
	f.Add([]byte{0x45})
	f.Add([]byte{0x60})
	f.Fuzz(func(t *testing.T, bytes []byte) {
		packet, err := checkedIPPacket(bytes)
		if err != nil {
			return
		}
		if reply := echoReply(packet); reply != nil {
			if _, err := checkedIPPacket(reply); err != nil {
				t.Fatalf("synthesized malformed reply: %v", err)
			}
		}
	})
}
