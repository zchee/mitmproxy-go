// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	miekg "codeberg.org/miekg/dns"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

// TestReverseDNSAuthoritativeTransports is a preservation row for real origin delivery.
func TestReverseDNSAuthoritativeTransports(t *testing.T) {
	tests := map[string]struct{ network string }{"UDP": {"udp"}, "TCP": {"tcp"}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, m, lifecycle := fixture(t)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "eager", "Server connection strategy."); err != nil {
				t.Fatal(err)
			}
			hooks := &dnsHooks{requests: make(chan *flow.DNSFlow, 2), responses: make(chan *flow.DNSFlow, 2), errors: make(chan *flow.DNSFlow, 2)}
			if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options), hooks); err != nil {
				t.Fatal(err)
			}
			started, served, done := make(chan struct{}), make(chan error, 1), make(chan error, 1)
			origin := miekg.NewServer()
			origin.Addr, origin.Net = "127.0.0.1:0", tt.network
			origin.ReadTimeout, origin.IdleTimeout = 30*time.Second, 30*time.Second
			origin.NotifyStartedFunc = func(context.Context) { close(started) }
			origin.Handler = miekg.HandlerFunc(func(_ context.Context, w miekg.ResponseWriter, request *miekg.Msg) {
				answer := &miekg.A{Hdr: miekg.Header{Name: "example.test.", TTL: 60, Class: miekg.ClassINET}}
				answer.Addr = netip.MustParseAddr("192.0.2.1")
				response := &miekg.Msg{ID: request.ID, Response: true, Authoritative: true, RecursionDesired: request.RecursionDesired, Question: request.Question, Answer: []miekg.RR{answer}}
				_, err := response.WriteTo(w)
				served <- err
			})
			go func() { done <- origin.ListenAndServe() }()
			await(t, started)
			t.Cleanup(func() {
				origin.Shutdown(context.WithoutCancel(t.Context()))
				if err := await(t, done); err != nil {
					t.Error(err)
				}
			})
			var address string
			if tt.network == "tcp" {
				address = origin.Listener.Addr().String()
			} else {
				address = origin.PacketConn.LocalAddr().String()
			}
			instance := makeInstance(t, "reverse:dns://"+address+"@127.0.0.1:0", cfg)
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			client := &miekg.Client{Transport: &miekg.Transport{Dialer: &net.Dialer{Timeout: 30 * time.Second}, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}}
			request := miekg.NewMsg("example.test", miekg.TypeA)
			delivered := make(chan struct {
				response *miekg.Msg
				err      error
			}, 1)
			go func() {
				response, _, err := client.Exchange(t.Context(), request, tt.network, instance.ListenAddrs()[0].String())
				delivered <- struct {
					response *miekg.Msg
					err      error
				}{response, err}
			}()
			admitted, requestDelivered, originReplied := false, false, false
			progress := func() string {
				return fmt.Sprintf("admitted=%t request delivered=%t origin replied=%t; pending response hooks=%d error hooks=%d client deliveries=%d", admitted, requestDelivered, originReplied, len(hooks.responses), len(hooks.errors), len(delivered))
			}
			awaitFixtureSignal(t, lifecycle.connected, "DNS client admission", progress)
			admitted = true
			requestFlow := awaitFixtureSignal(t, hooks.requests, "DNS request delivery", progress)
			requestDelivered = true
			if err := awaitFixtureSignal(t, served, "DNS origin reply", progress); err != nil {
				t.Fatal(err)
			}
			originReplied = true
			result := awaitFixtureSignal(t, delivered, "DNS client response delivery", progress)
			if result.err != nil {
				stack := make([]byte, 1<<20)
				t.Fatalf("DNS exchange: %v; %s\n%s", result.err, progress(), stack[:runtime.Stack(stack, true)])
			}
			response := result.response
			if !response.Response || !response.Authoritative || response.ID != request.ID || len(response.Answer) != 1 {
				t.Fatalf("unexpected authoritative response: %s", response)
			}
			answer, ok := response.Answer[0].(*miekg.A)
			if !ok {
				t.Fatalf("answer type = %T", response.Answer[0])
			}
			if diff := gocmp.Diff("192.0.2.1", answer.Addr.String()); diff != "" {
				t.Fatal(diff)
			}
			if answer.Hdr.TTL != 60 {
				t.Fatalf("upstream TTL changed: %d", answer.Hdr.TTL)
			}
			if requestFlow != awaitFixtureSignal(t, hooks.responses, "DNS response hook", progress) {
				t.Fatal("request and response used different flows")
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
