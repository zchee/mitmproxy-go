// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package debugserver

import (
	"net"
	"net/netip"
	"testing"
)

func FuzzPprofAddress(f *testing.F) {
	f.Add("")
	f.Add("127.0.0.1:0")
	f.Add("[::1]:6060")
	f.Add("0.0.0.0:6060")
	f.Fuzz(func(t *testing.T, value string) {
		address, err := parseAddress(value)
		if err != nil || value == "" {
			if address != "" {
				t.Fatalf("empty or refused input returned an address: %q", address)
			}
			return
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsLoopback() || ip.Zone() != "" || ip.Is4In6() {
			t.Fatalf("parser accepted a noncanonical or nonloopback address: %q", address)
		}
		if again, err := parseAddress(address); err != nil || again != address {
			t.Fatalf("canonical address is not stable: %q -> %q, %v", address, again, err)
		}
	})
}
