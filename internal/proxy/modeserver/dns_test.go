// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

type dnsHooks struct {
	requests  chan *flow.DNSFlow
	responses chan *flow.DNSFlow
	errors    chan *flow.DNSFlow
}

func (h *dnsHooks) DNSRequest(_ context.Context, f *flow.DNSFlow) error { h.requests <- f; return nil }

func (h *dnsHooks) DNSResponse(_ context.Context, f *flow.DNSFlow) error {
	h.responses <- f
	return nil
}
func (h *dnsHooks) DNSError(_ context.Context, f *flow.DNSFlow) error { h.errors <- f; return nil }

func TestReverseDNSUDPForwarding(t *testing.T) {
	cfg, m, _ := fixture(t)
	if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "eager", "Server connection strategy."); err != nil {
		t.Fatal(err)
	}
	hooks := &dnsHooks{requests: make(chan *flow.DNSFlow, 4), responses: make(chan *flow.DNSFlow, 4), errors: make(chan *flow.DNSFlow, 4)}
	if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options), hooks); err != nil {
		t.Fatal(err)
	}
	origin, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = origin.Close() }()
	if err := origin.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	originDone := make(chan error, 1)
	go func() {
		var buf [65535]byte
		n, peer, err := origin.ReadFrom(buf[:])
		if err != nil {
			originDone <- err
			return
		}
		request, err := dns.Unpack(buf[:n], nil)
		if err != nil {
			originDone <- err
			return
		}
		response := request.Succeed([]dns.ResourceRecord{dns.A("example.test", netip.MustParseAddr("192.0.2.1"), 60)})
		wire, err := dns.Pack(response)
		if err == nil {
			_, err = origin.WriteTo(wire, peer)
		}
		originDone <- err
	}()
	instance := makeInstance(t, "reverse:dns://"+origin.LocalAddr().String()+"@127.0.0.1:0", cfg)
	if err := instance.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("udp4", instance.ListenAddrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := &dns.Message{ID: 7, Query: true, RecursionDesired: true, Questions: []dns.Question{{Name: "example.test", Type: dns.TypeA, Class: dns.ClassIN}}}
	wire, err := dns.Pack(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(wire); err != nil {
		t.Fatal(err)
	}
	var buf [65535]byte
	n, err := client.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	response, err := dns.Unpack(buf[:n], nil)
	if err != nil {
		t.Fatal(err)
	}
	want := request.Succeed([]dns.ResourceRecord{dns.A("example.test", netip.MustParseAddr("192.0.2.1"), 60)})
	want.Timestamp = nil
	if diff := gocmp.Diff(want, response); diff != "" {
		t.Fatal(diff)
	}
	if err := await(t, originDone); err != nil {
		t.Fatal(err)
	}
	f := await(t, hooks.requests)
	if await(t, hooks.responses) != f {
		t.Fatal("request and response used different DNS flows")
	}
	select {
	case <-hooks.errors:
		t.Fatal("successful forwarding fired DNS error hook")
	default:
	}
	if err := instance.Stop(); err != nil {
		t.Fatal(err)
	}
}
