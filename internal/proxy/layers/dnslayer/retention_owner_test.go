// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"testing"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
)

// Certification: completion releases only the original transaction key, after
// finalizing its flow in addon dispatch. Suppressed replies retain that entry.
func TestDNSTransactionMap(t *testing.T) {
	tests := map[string]struct{ failed, removeResponse, requestless, udp bool }{
		"success: TCP response evicts original ID":              {},
		"success: TCP error evicts original ID":                 {failed: true},
		"success: TCP removed response remains retained":        {removeResponse: true},
		"success: UDP response evicts original ID":              {udp: true},
		"success: UDP error evicts original ID":                 {failed: true, udp: true},
		"success: UDP removed response remains retained":        {removeResponse: true, udp: true},
		"success: TCP unsolicited response evicts original ID":  {requestless: true},
		"success: UDP unsolicited response evicts original ID":  {requestless: true, udp: true},
		"success: TCP suppressed unsolicited response retained": {requestless: true, removeResponse: true},
		"success: UDP suppressed unsolicited response retained": {requestless: true, removeResponse: true, udp: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, tt.udp, &observer{
				response: func(_ context.Context, f *flow.DNSFlow) error {
					f.Response.ID = 23
					if tt.removeResponse {
						f.Response = nil
					}
					return nil
				},
				failed: func(_ context.Context, f *flow.DNSFlow) error { f.Request.ID = 23; return nil },
			})
			f := flow.NewDNSFlow(s.context.Data.Client, s.context.Data.Server, true)
			if !tt.requestless {
				f.Request = query(17)
			}
			other := flow.NewDNSFlow(s.context.Data.Client, s.context.Data.Server, true)
			o := &owner{ctx: t.Context(), c: s.context, flows: map[int]*flow.DNSFlow{17: f, 23: other}}
			finalizedWhileRetained := false
			dispatch := s.context.Do
			s.context.Do = func(ctx context.Context, fn func(context.Context) error) error {
				return dispatch(ctx, func(ctx context.Context) error {
					if err := fn(ctx); err != nil {
						return err
					}
					if !f.Live && !f.Intercepted() && o.flows[17] == f {
						finalizedWhileRetained = true
					}
					return nil
				})
			}
			var err error
			if tt.failed {
				err = o.fail(17, f, "resolver failed")
			} else {
				err = o.response(17, f, query(17).Succeed(nil))
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.requestless && f.Request != nil {
				t.Fatal("unsolicited response acquired a request")
			}
			if tt.removeResponse {
				if len(o.flows) != 2 || o.flows[17] != f || !f.Live || finalizedWhileRetained {
					t.Fatal("hook-suppressed response lost its retained live entry")
				}
				return
			}
			if !finalizedWhileRetained {
				t.Fatal("flow was deleted before finalization in addon dispatch")
			}
			if got := s.read(t); got.ID != 23 {
				t.Fatalf("hook-edited reply ID = %d, want 23", got.ID)
			}
			if len(o.flows) != 1 || o.flows[23] != other {
				t.Fatalf("completion retained original key or evicted another ID: %v", o.flows)
			}
			if f.Live || f.Intercepted() {
				t.Fatal("evicted flow is still live or intercepted")
			}
		})
	}
}

// Certification: a paused response still belongs to the owner until its hook
// resumes and forwarding finishes. Its sole map reference cannot be dropped live.
func TestDNSInterceptedResponseRetention(t *testing.T) {
	paused := make(chan *flow.DNSFlow, 1)
	s := newSession(t, false, &observer{response: func(_ context.Context, f *flow.DNSFlow) error {
		f.Intercept()
		paused <- f
		return nil
	}})
	f := flow.NewDNSFlow(s.context.Data.Client, s.context.Data.Server, true)
	f.Request = query(17)
	o := &owner{ctx: t.Context(), c: s.context, flows: map[int]*flow.DNSFlow{17: f}}
	finished := make(chan error, 1)
	go func() { finished <- o.response(17, f, query(17).Succeed([]dns.ResourceRecord{})) }()
	await(t, paused)
	if err := s.manager.Do(t.Context(), func(context.Context) error {
		if len(o.flows) != 1 || o.flows[17] != f || !f.Live || !f.Intercepted() {
			t.Error("paused response lost its live map reference")
		}
		f.Resume()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := await(t, finished); err != nil {
		t.Fatal(err)
	}
	if got := s.read(t); got.ID != 17 {
		t.Fatalf("resumed response ID = %d", got.ID)
	}
	if len(o.flows) != 0 || f.Live || f.Intercepted() {
		t.Fatal("resumed response was not finalized and evicted")
	}
}

// Preservation: an unanswered retransmission shares its flow, fires a request
// hook per arrival and forwards again; only the answer fires dns_response.
func TestDNSRetransmitBeforeResponse(t *testing.T) {
	tests := map[string]struct{ udp bool }{
		"success: TCP unanswered retransmit": {},
		"success: UDP unanswered retransmit": {udp: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, tt.udp, nil)
			origin := newSession(t, tt.udp, nil)
			s.context.Server, s.context.ServerPackets = origin.context.Client, origin.context.ClientPackets
			s.context.Data.Server.Address = s.context.Data.Client.Sockname
			s.start(t)
			for range 2 {
				s.write(t, query(17))
				if got := origin.read(t); got.ID != 17 || !got.Query {
					t.Fatalf("forwarded retransmit = %+v", got)
				}
			}
			origin.write(t, query(17).Succeed(nil))
			if got := s.read(t); got.ID != 17 {
				t.Fatalf("response ID = %d", got.ID)
			}
			s.stop(t)
			if len(s.observed.flows) != 2 || s.observed.flows[0] != s.observed.flows[1] {
				t.Fatal("unanswered resend created another flow")
			}
			if len(s.observed.events) != 3 || s.observed.events[0] != "dns_request" || s.observed.events[1] != "dns_request" || s.observed.events[2] != "dns_response" {
				t.Fatalf("retransmit hooks = %v", s.observed.events)
			}
		})
	}
}
