// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	miekg "codeberg.org/miekg/dns"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
)

type dnsAnswerHooks struct{ dnsHooks }

func (h *dnsAnswerHooks) DNSRequest(ctx context.Context, f *flow.DNSFlow) error {
	f.Response = f.Request.Succeed([]dns.ResourceRecord{dns.A("example.test", netip.MustParseAddr("192.0.2.1"), 60)})
	return h.dnsHooks.DNSRequest(ctx, f)
}

// This verifies listener-to-hook wiring with an independent real DNS client.
// Default-resolver authoritative-server acceptance awaits resolver integration.
func TestStandaloneDNSWireTransports(t *testing.T) {
	tests := map[string]struct{ network, host string }{
		"IPv4 UDP": {"udp", "127.0.0.1"}, "IPv4 TCP": {"tcp", "127.0.0.1"},
		"IPv6 UDP": {"udp", "::1"}, "IPv6 TCP": {"tcp", "::1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.host == "::1" {
				probe, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				_ = probe.Close()
			}
			cfg, m, _ := fixture(t)
			hooks := &dnsAnswerHooks{dnsHooks{requests: make(chan *flow.DNSFlow, 2), responses: make(chan *flow.DNSFlow, 2), errors: make(chan *flow.DNSFlow, 2)}}
			if err := m.Addons.Add(t.Context(), hooks); err != nil {
				t.Fatal(err)
			}
			instance := makeInstance(t, "dns@"+net.JoinHostPort(tt.host, "0"), cfg)
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			client := &miekg.Client{Transport: &miekg.Transport{Dialer: &net.Dialer{Timeout: 30 * time.Second}, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}}
			request := miekg.NewMsg("example.test", miekg.TypeA)
			response, _, err := client.Exchange(t.Context(), request, tt.network, instance.ListenAddrs()[0].String())
			if err != nil {
				t.Fatal(err)
			}
			if !response.Response || response.ID != request.ID || response.Rcode != 0 || len(response.Answer) != 1 {
				t.Fatalf("unexpected DNS response: %s", response)
			}
			answer, ok := response.Answer[0].(*miekg.A)
			if !ok {
				t.Fatalf("answer type = %T", response.Answer[0])
			}
			if diff := gocmp.Diff(miekg.Header{Name: "example.test.", TTL: 60, Class: miekg.ClassINET}, answer.Hdr); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff("192.0.2.1", answer.Addr.String()); diff != "" {
				t.Fatal(diff)
			}
			if await(t, hooks.requests) != await(t, hooks.responses) {
				t.Fatal("request and response used different flows")
			}
			select {
			case <-hooks.errors:
				t.Fatal("successful answer fired dns_error")
			default:
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
