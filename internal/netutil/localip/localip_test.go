// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package localip

import (
	"net/netip"
	"testing"
)

// Like upstream's test_local_ip.py, these calls must never panic; whether
// they find an address depends on the host's network configuration.
func TestGetLocalIP(t *testing.T) {
	tests := map[string]struct {
		family Family
		want   func(netip.Addr) bool
	}{
		"success: IPv4 default route": {family: IPv4, want: netip.Addr.Is4},
		"success: IPv6 default route": {family: IPv6, want: netip.Addr.Is6},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addr, err := GetLocalIP(tt.family)
			if err != nil {
				t.Logf("GetLocalIP(%d) error, the host has no such route: %v", tt.family, err)
				return
			}
			if !tt.want(addr) {
				t.Errorf("GetLocalIP(%d) = %v, wrong family", tt.family, addr)
			}
			if addr.IsUnspecified() {
				t.Errorf("GetLocalIP(%d) = %v, want a specific address", tt.family, addr)
			}
		})
	}
}

func TestGetLocalIPVia(t *testing.T) {
	tests := map[string]struct {
		family    Family
		reachable string
		want      netip.Addr
		wantErr   bool
		// mayFail marks destinations whose outcome depends on the host.
		mayFail bool
	}{
		"success: IPv4 loopback": {
			family: IPv4, reachable: "127.0.0.1", want: netip.MustParseAddr("127.0.0.1"),
		},
		"success: IPv6 loopback": {
			family: IPv6, reachable: "::1", want: netip.MustParseAddr("::1"), mayFail: true,
		},
		"error: invalid host name":     {family: IPv4, reachable: "invalid!", wantErr: true},
		"error: IPv6 address for IPv4": {family: IPv4, reachable: "::1", wantErr: true},
		"error: IPv4 address for IPv6": {family: IPv6, reachable: "127.0.0.1", wantErr: true},
		"success: IPv4 unspecified":    {family: IPv4, reachable: "0.0.0.0", mayFail: true},
		"success: IPv6 unspecified":    {family: IPv6, reachable: "::", mayFail: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addr, err := GetLocalIPVia(tt.family, tt.reachable)
			switch {
			case tt.wantErr:
				if err == nil {
					t.Fatalf("GetLocalIPVia(%d, %q) = %v, want error", tt.family, tt.reachable, addr)
				}
				return
			case err != nil && tt.mayFail:
				t.Logf("GetLocalIPVia(%d, %q) error on this host: %v", tt.family, tt.reachable, err)
				return
			case err != nil:
				t.Fatalf("GetLocalIPVia(%d, %q) error: %v", tt.family, tt.reachable, err)
			}
			if tt.want.IsValid() && addr != tt.want {
				t.Errorf("GetLocalIPVia(%d, %q) = %v, want %v", tt.family, tt.reachable, addr, tt.want)
			}
		})
	}
}
