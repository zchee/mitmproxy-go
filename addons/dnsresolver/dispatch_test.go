// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestPendingLookupDispatch(t *testing.T) {
	tests := map[string]struct{ cancel bool }{
		"configuration invalidates pending cache": {},
		"cancellation leaves flow untouched":      {cancel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			received := make(chan struct{}, 1)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				buffer := make([]byte, 65535)
				for {
					n, peer, err := conn.ReadFromUDP(buffer)
					if err != nil {
						return
					}
					select {
					case received <- struct{}{}:
					default:
					}
					<-release
					request, err := dns.Unpack(buffer[:n], nil)
					if err != nil {
						t.Error(err)
						return
					}
					response := request.Succeed(nil)
					wire, err := dns.Pack(response)
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := conn.WriteToUDP(wire, peer); err != nil {
						return
					}
				}
			}()
			t.Cleanup(func() { unblock(); _ = conn.Close(); <-serverDone })
			opts := options.New()
			manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
			t.Cleanup(manager.Close)
			r := New(opts, nil)
			r.port = conn.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			r.hostsPath = t.TempDir() + "/missing-hosts"
			if err := manager.Add(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"dns_name_servers": []string{"127.0.0.1"}, "dns_use_hosts_file": false})
			}); err != nil {
				t.Fatal(err)
			}
			f := flow.NewDNSFlow(&connection.Client{ProxyMode: "dns"}, connection.NewServer(nil), true)
			f.Request = &dns.Message{ID: 42, Query: true, Questions: []dns.Question{{Name: "empty.example", Type: dns.TypeA, Class: dns.ClassIN}}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- manager.Trigger(ctx, addon.DNSRequestHook{Flow: f}) }()
			select {
			case <-received:
			case <-time.After(10 * time.Second):
				stack := make([]byte, 1<<20)
				t.Fatalf("DNS server did not receive lookup:\n%s", stack[:runtime.Stack(stack, true)])
			}
			if tt.cancel {
				cancel()
			} else {
				if err := manager.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, map[string]any{"dns_use_hosts_file": true}) }); err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				stack := make([]byte, 1<<20)
				t.Fatalf("lookup did not finish:\n%s", stack[:runtime.Stack(stack, true)])
			}
			if r.cached != nil {
				t.Fatal("cancelled or stale-generation lookup repopulated cache")
			}
			if tt.cancel && (f.Response != nil || f.Error != nil) {
				t.Fatal("cancelled lookup changed flow")
			}
			if !tt.cancel && f.Response == nil {
				t.Fatal("lookup failed to commit under dispatch")
			}
		})
	}
}
