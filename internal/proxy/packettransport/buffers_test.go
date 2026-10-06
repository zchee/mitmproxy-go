// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package packettransport

import (
	"errors"
	"net"
	"testing"
)

func TestConfigureSocketBuffers(t *testing.T) {
	tests := map[string]struct{ closed bool }{"open socket": {}, "closed socket fails admission": {closed: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = socket.Close() })
			if test.closed {
				if err := socket.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err = ConfigureSocketBuffers(socket)
			if test.closed {
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed socket configuration = %v", err)
				}
				listener := NewListener(t.Context(), socket)
				t.Cleanup(func() { _ = listener.Close() })
				if _, err := listener.Accept(t.Context()); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed listener admission = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
