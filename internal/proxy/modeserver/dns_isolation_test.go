// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

type dnsResolver struct{ dnsHooks }

func (h *dnsResolver) DNSRequest(ctx context.Context, f *flow.DNSFlow) error {
	f.Response = f.Request.Succeed(nil)
	return h.dnsHooks.DNSRequest(ctx, f)
}

func TestMalformedDNSTupleIsolation(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	cfg, m, lifecycle := fixture(t)
	if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "eager", "Server connection strategy."); err != nil {
		t.Fatal(err)
	}
	hooks := &dnsResolver{requests: make(chan *flow.DNSFlow, 4), responses: make(chan *flow.DNSFlow, 4), errors: make(chan *flow.DNSFlow, 4)}
	if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options), hooks); err != nil {
		t.Fatal(err)
	}
	instance := makeInstance(t, "reverse:dns://127.0.0.1:53@127.0.0.1:0", cfg)
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	dial := func() net.Conn {
		conn, err := net.Dial("udp4", instance.ListenAddrs()[0].String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	bad, healthy := dial(), dial()
	if _, err := bad.Write([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	await(t, lifecycle.disconnected)
	select {
	case <-hooks.requests:
		t.Fatal("malformed query created a DNS flow")
	case <-hooks.errors:
		t.Fatal("malformed query fired dns_error")
	default:
	}
	request := &dns.Message{ID: 10, Query: true, Questions: []dns.Question{{Name: "example.test", Type: dns.TypeA, Class: dns.ClassIN}}}
	wire, err := dns.Pack(request)
	if err != nil {
		t.Fatal(err)
	}
	var previous *flow.DNSFlow
	for _, conn := range []net.Conn{healthy, bad} {
		if _, err := conn.Write(wire); err != nil {
			t.Fatal(err)
		}
		var buf [65535]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		response, err := dns.Unpack(buf[:n], nil)
		if err != nil {
			t.Fatal(err)
		}
		if response.Query || response.ID != 10 {
			t.Fatalf("response = %+v", response)
		}
		f := await(t, hooks.requests)
		if await(t, hooks.responses) != f {
			t.Fatal("response did not match request flow")
		}
		if f == previous {
			t.Fatal("different tuple reused a DNS flow")
		}
		previous = f
	}
	if err := instance.Stop(); err != nil {
		t.Fatal(err)
	}
	await(t, lifecycle.disconnected)
	await(t, lifecycle.disconnected)
}
