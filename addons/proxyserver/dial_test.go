// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver

import (
	"net"
	"strconv"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestDialControlResolvedAddresses(t *testing.T) {
	const refused = "Request destination unknown. Unable to figure out where this request should be forwarded to."
	tests := map[string]struct {
		resolved string
	}{
		"error: 127.1 resolved by libc":      {resolved: "127.0.0.1"},
		"error: 2130706433 resolved by libc": {resolved: "127.0.0.1"},
		"error: 0x7f000001 resolved by libc": {resolved: "127.0.0.1"},
		"error: 0x7f.1 resolved by libc":     {resolved: "127.0.0.1"},
		"error: IPv4-mapped loopback":        {resolved: "::ffff:127.0.0.1"},
		"error: IPv6 loopback":               {resolved: "::1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, ps, _, _ := fixture(t, false)
			if err := ps.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			port := ps.ListenAddrs()[0].Port
			address := net.JoinHostPort(tt.resolved, strconv.Itoa(port))
			err := ps.dialControl("tcp", address, nil)
			if err == nil {
				t.Fatalf("Control accepted resolved listener address %s", address)
			}
			if diff := gocmp.Diff(refused, err.Error()); diff != "" {
				t.Fatal(diff)
			}
			other := net.JoinHostPort(tt.resolved, strconv.Itoa(port+1))
			if err := ps.dialControl("tcp", other, nil); err != nil {
				t.Fatalf("Control refused another port %s: %v", other, err)
			}
			if err := ps.dialControl("tcp", net.JoinHostPort("192.0.2.1", strconv.Itoa(port)), nil); err != nil {
				t.Fatalf("Control refused a remote address: %v", err)
			}
		})
	}
}
