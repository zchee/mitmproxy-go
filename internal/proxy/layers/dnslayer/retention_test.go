// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

// Intentional deviation: completed IDs are evicted and the flow is finalized
// before a later request with the same ID enters dns_request. Upstream retains it.
func TestDNSTransactionCompletion(t *testing.T) {
	tests := map[string]struct{ udp, failed bool }{
		"success: TCP resend after the answer creates a new flow": {},
		"success: UDP resend after the answer creates a new flow": {udp: true},
		"success: TCP error then resend":                          {failed: true},
		"success: UDP error then resend":                          {udp: true, failed: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var previous *flow.DNSFlow
			a := &observer{request: func(_ context.Context, f *flow.DNSFlow) error {
				if previous != nil {
					if f == previous {
						t.Error("resend after the answer reused the completed flow")
					}
					if previous.Live || previous.Intercepted() {
						t.Error("completed flow remained live before the next request")
					}
				}
				previous = f
				if tt.failed {
					f.Error = flow.NewError("resolver failed")
				} else {
					f.Response = f.Request.Succeed(nil)
				}
				return nil
			}}
			s := newSession(t, tt.udp, a)
			s.start(t)
			for range 2 {
				s.write(t, query(17))
				if got := s.read(t); got.ID != 17 {
					t.Fatalf("reply ID = %d, want 17", got.ID)
				}
			}
			s.stop(t)
			terminal := "dns_response"
			if tt.failed {
				terminal = "dns_error"
			}
			if diff := gocmp.Diff([]string{"dns_request", terminal, "dns_request", terminal}, a.events); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// Intentional deviation: a late response after eviction takes the preservation
// path for a never-seen ID: a new requestless flow and an unchanged wire reply.
func TestDNSLateResponseAfterCompletion(t *testing.T) {
	tests := map[string]struct{ udp bool }{
		"success: TCP late response": {},
		"success: UDP late response": {udp: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var first *flow.DNSFlow
			responses := 0
			a := &observer{response: func(_ context.Context, f *flow.DNSFlow) error {
				responses++
				if responses == 1 {
					first = f
				} else {
					if f == first || f.Request != nil {
						t.Error("late response reused the completed request flow")
					}
					if first.Live || first.Intercepted() {
						t.Error("first response flow was not finalized")
					}
				}
				return nil
			}}
			s := newSession(t, tt.udp, a)
			origin := newSession(t, tt.udp, nil)
			s.context.Server, s.context.ServerPackets = origin.context.Client, origin.context.ClientPackets
			s.context.Data.Server.Address = &connection.Address{Host: "example.test", Port: 53}
			s.start(t)
			s.write(t, query(23))
			if got := origin.read(t); got.ID != 23 || !got.Query {
				t.Fatalf("upstream request = %+v", got)
			}
			want := query(23).Succeed([]dns.ResourceRecord{})
			want.Timestamp = nil
			for range 2 {
				origin.write(t, want)
				got := s.read(t)
				got.Timestamp = nil
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Fatal(diff)
				}
			}
			s.stop(t)
			if diff := gocmp.Diff([]string{"dns_request", "dns_response", "dns_response"}, a.events); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

// Intentional deviation: the 1,025th distinct unanswered ID ends the transport
// through the invalid-message path; an existing ID still fits at the bound.
func TestDNSOutstandingTransactionLimit(t *testing.T) {
	tests := map[string]struct{ udp bool }{
		"error: TCP outstanding bound":       {},
		"error: UDP tuple outstanding bound": {udp: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			requests := make(chan int, 1)
			a := &observer{request: func(_ context.Context, f *flow.DNSFlow) error { requests <- f.Request.ID; return nil }}
			s := newSession(t, tt.udp, a)
			origin := newSession(t, tt.udp, nil)
			s.context.Server, s.context.ServerPackets = origin.context.Client, origin.context.ClientPackets
			s.context.Data.Server.Address = &connection.Address{Host: "example.test", Port: 53}
			s.start(t)
			for id := range 1024 {
				s.write(t, query(id))
				if got := await(t, requests); got != id {
					t.Fatalf("request hook ID = %d, want %d", got, id)
				}
				if got := origin.read(t); got.ID != id {
					t.Fatalf("forwarded request ID = %d, want %d", got.ID, id)
				}
			}
			s.write(t, query(0))
			if got := await(t, requests); got != 0 {
				t.Fatalf("at-bound retransmit ID = %d", got)
			}
			if got := origin.read(t); got.ID != 0 {
				t.Fatalf("forwarded retransmit ID = %d", got.ID)
			}
			s.write(t, query(1024))
			select {
			case err := <-s.done:
				if err == nil || !strings.Contains(err.Error(), "outstanding DNS transaction limit") {
					t.Fatalf("limit result = %v", err)
				}
			case id := <-requests:
				t.Fatalf("over-limit ID %d reached dns_request", id)
			case <-time.After(layertest.Timeout):
				t.Fatal("over-limit request did not terminate the DNS layer")
			}
			await(t, s.finished)
			if !strings.Contains(s.logs.String(), "sent an invalid message:") {
				t.Fatalf("limit diagnostic = %q", s.logs.String())
			}
			for index, f := range a.flows {
				if f.Live || f.Intercepted() {
					t.Errorf("outstanding flow %d was not finalized", index)
				}
			}
		})
	}
}
