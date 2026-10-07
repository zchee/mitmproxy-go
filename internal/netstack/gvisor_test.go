// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestGVisorAdapter(t *testing.T) {
	tests := map[string]struct {
		clock tcpip.Clock
	}{
		"default clock":  {},
		"injected clock": {clock: faketime.NewManualClock()},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, link, err := newGVisor(tt.clock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { link.Close(); s.Destroy() })
			if link.MTU() != 1420 || !link.IsAttached() {
				t.Fatalf("link MTU = %d, attached = %v", link.MTU(), link.IsAttached())
			}
			if tt.clock != nil && s.Clock() != tt.clock {
				t.Fatal("stack did not retain the injected clock")
			}
			if got := len(s.GetRouteTable()); got != 2 {
				t.Fatalf("default route count = %d, want 2", got)
			}
			for _, protocol := range []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber} {
				if !s.CheckNetworkProtocol(protocol) {
					t.Fatalf("network protocol %d missing", protocol)
				}
				for _, transport := range []tcpip.TransportProtocolNumber{tcp.ProtocolNumber, udp.ProtocolNumber} {
					var queue waiter.Queue
					ep, endpointErr := s.NewEndpoint(transport, protocol, &queue)
					if endpointErr != nil {
						t.Fatalf("endpoint %d/%d: %s", protocol, transport, endpointErr)
					}
					// Binding a nonlocal address verifies spoofing without assigning it to the NIC.
					addr := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
					if protocol == header.IPv6ProtocolNumber {
						addr = tcpip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
					}
					bindErr := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: addr, Port: 1234})
					ep.Close()
					if bindErr != nil {
						t.Fatalf("bind nonlocal %d/%d: %s", protocol, transport, bindErr)
					}
				}
			}
			var send tcpip.TCPSendBufferSizeRangeOption
			if optionErr := s.TransportProtocolOption(tcp.ProtocolNumber, &send); optionErr != nil {
				t.Fatal(optionErr)
			}
			want := tcpip.TCPSendBufferSizeRangeOption{Min: 65536, Default: 65536, Max: 65536}
			if diff := gocmp.Diff(want, send); diff != "" {
				t.Fatalf("TCP send buffer (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGVisorClockTimers(t *testing.T) {
	tests := map[string]struct{ duration time.Duration }{
		"keepalive duration":    {duration: 28 * time.Second},
		"tuple expiry duration": {duration: 60 * time.Second},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			s, link, err := newGVisor(clock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { link.Close(); s.Destroy() })
			fired := false
			timer := s.Clock().AfterFunc(tt.duration, func() { fired = true })
			t.Cleanup(func() { timer.Stop() })
			clock.Advance(tt.duration - time.Nanosecond)
			if fired {
				t.Fatal("timer fired before its deadline")
			}
			clock.Advance(time.Nanosecond)
			if !fired {
				t.Fatal("timer did not fire at its deadline")
			}
		})
	}
}
