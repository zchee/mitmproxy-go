// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"net/netip"
	"testing"
)

func TestWindowsSystemConfiguration(t *testing.T) {
	cfg, err := systemConfiguration("")
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range cfg.servers {
		if _, err := netip.ParseAddr(server); err != nil {
			t.Fatalf("invalid IP Helper DNS address %q: %v", server, err)
		}
	}
}
