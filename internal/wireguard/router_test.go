// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestPacketAddresses certifies bounded address extraction for routing.
func TestPacketAddresses(t *testing.T) {
	ipv4Source, ipv4Destination := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("198.51.100.7")
	ipv6Source, ipv6Destination := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::42")
	ipv4 := serverTestEchoPacket(ipv4Destination, ipv4Source)
	ipv6 := serverTestEchoPacket(ipv6Destination, ipv6Source)
	oversized := bytes.Clone(ipv4)
	binary.BigEndian.PutUint16(oversized[2:], 65535)
	tests := map[string]struct {
		packet              []byte
		source, destination string
		valid               bool
	}{
		"success: IPv4 addresses": {packet: ipv4, source: ipv4Source.String(), destination: ipv4Destination.String(), valid: true},
		"success: IPv6 addresses": {packet: ipv6, source: ipv6Source.String(), destination: ipv6Destination.String(), valid: true},
		"error: empty packet":     {},
		"error: unknown version":  {packet: []byte{0}},
		"error: short IPv4":       {packet: ipv4[:1]},
		"error: short IPv6":       {packet: ipv6[:1]},
		"error: truncated IPv4":   {packet: oversized},
		"error: truncated IPv6":   {packet: ipv6[:40]},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			source, destination, valid := packetAddresses(test.packet)
			if valid != test.valid {
				t.Fatalf("valid = %v, want %v", valid, test.valid)
			}
			if valid {
				if diff := gocmp.Diff([]string{test.source, test.destination}, []string{source.String(), destination.String()}); diff != "" {
					t.Errorf("packet addresses (-want +got):\n%s", diff)
				}
			}
		})
	}
}
