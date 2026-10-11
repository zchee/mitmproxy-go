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

// Preservation: the 1,025th distinct retained ID ends the transport
// through the invalid-message path; an existing ID still fits at the bound.
func TestDNSRetainedTransactionLimit(t *testing.T) {
	tests := map[string]struct{ udp, suppressResponses, newResponse bool }{
		"error: TCP unanswered retained bound":                {},
		"error: UDP unanswered retained bound":                {udp: true},
		"error: TCP suppressed replies refuse a new request":  {suppressResponses: true},
		"error: UDP suppressed replies refuse a new request":  {udp: true, suppressResponses: true},
		"error: TCP suppressed replies refuse a new response": {suppressResponses: true, newResponse: true},
		"error: UDP suppressed replies refuse a new response": {udp: true, suppressResponses: true, newResponse: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			arrivals := make(chan *flow.DNSFlow, 1)
			a := &observer{
				request: func(_ context.Context, f *flow.DNSFlow) error { arrivals <- f; return nil },
				response: func(_ context.Context, f *flow.DNSFlow) error {
					if f.Request != nil {
						t.Error("initial unsolicited response has a request")
					}
					f.Response = nil
					arrivals <- f
					return nil
				},
			}
			s := newSession(t, tt.udp, a)
			origin := newSession(t, tt.udp, nil)
			s.context.Server, s.context.ServerPackets = origin.context.Client, origin.context.ClientPackets
			s.context.Data.Server.Address = &connection.Address{Host: "example.test", Port: 53}
			s.start(t)
			retained := make([]*flow.DNSFlow, 0, 1024)
			for id := range 1024 {
				if tt.suppressResponses {
					origin.write(t, query(id).Succeed(nil))
				} else {
					s.write(t, query(id))
				}
				f := await(t, arrivals)
				retained = append(retained, f)
				if !tt.suppressResponses {
					if f.Request.ID != id {
						t.Fatalf("request hook ID = %d, want %d", f.Request.ID, id)
					}
					if got := origin.read(t); got.ID != id {
						t.Fatalf("forwarded request ID = %d, want %d", got.ID, id)
					}
				}
			}
			s.write(t, query(0))
			if got := await(t, arrivals); got != retained[0] || got.Request.ID != 0 {
				t.Fatalf("at-bound retransmit flow = %p, want %p with ID 0", got, retained[0])
			}
			if got := origin.read(t); got.ID != 0 {
				t.Fatalf("forwarded retransmit ID = %d", got.ID)
			}
			if tt.newResponse {
				origin.write(t, query(1024).Succeed(nil))
			} else {
				s.write(t, query(1024))
			}
			select {
			case err := <-s.done:
				if err == nil || err.Error() != "dnslayer: retained DNS transaction limit exceeded (1024)" {
					t.Fatalf("limit result = %v", err)
				}
			case f := <-arrivals:
				t.Fatalf("over-limit message reached a DNS hook: %+v", f)
			case <-time.After(layertest.Timeout):
				t.Fatal("over-limit request did not terminate the DNS layer")
			}
			await(t, s.finished)
			if !strings.Contains(s.logs.String(), "sent an invalid message:") {
				t.Fatalf("limit diagnostic = %q", s.logs.String())
			}
			for index, f := range retained {
				if f.Live || f.Intercepted() {
					t.Errorf("retained flow %d was not finalized", index)
				}
			}
		})
	}
}
