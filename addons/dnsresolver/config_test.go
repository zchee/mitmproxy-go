// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMissingNameServers(t *testing.T) {
	tests := map[string]struct {
		typ       int
		useHosts  bool
		name      string
		wantError bool
	}{
		"A no hosts":       {typ: dns.TypeA, name: "localhost", wantError: true},
		"AAAA no hosts":    {typ: dns.TypeAAAA, name: "localhost", wantError: true},
		"TXT hosts":        {typ: dns.TypeTXT, name: "localhost", useHosts: true, wantError: true},
		"TXT no hosts":     {typ: dns.TypeTXT, name: "localhost", wantError: true},
		"owned hosts IPv4": {typ: dns.TypeA, name: "fixture.invalid", useHosts: true},
		"owned hosts IPv6": {typ: dns.TypeAAAA, name: "fixture.invalid", useHosts: true},
		"literal IPv4":     {typ: dns.TypeA, name: "127.0.0.1", useHosts: true},
		"literal IPv6":     {typ: dns.TypeAAAA, name: "::1", useHosts: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
			t.Cleanup(manager.Close)
			r := New(opts, nil)
			r.hostsPath = filepath.Join(t.TempDir(), "hosts")
			if err := os.WriteFile(r.hostsPath, []byte("127.0.0.1 fixture.invalid\n::1 fixture.invalid\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var hosts map[string][]netip.Addr
			if tt.useHosts {
				var err error
				hosts, err = readHosts(r.hostsPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := manager.Add(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(context.Context) error {
				r.cached = &resolverConfig{useHosts: tt.useHosts, hosts: hosts}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			f := flow.NewDNSFlow(&connection.Client{ProxyMode: "dns"}, connection.NewServer(nil), true)
			f.Request = &dns.Message{Query: true, Questions: []dns.Question{{Name: tt.name, Type: tt.typ, Class: dns.ClassIN}}}
			if err := manager.Trigger(t.Context(), addon.DNSRequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if tt.wantError {
				if f.Error == nil || f.Error.Msg != "Cannot resolve, dns_name_servers unknown." {
					t.Fatalf("missing-server error = %v", f.Error)
				}
				if f.Response != nil {
					t.Fatal("missing-server query answered")
				}
				return
			}
			if f.Error != nil || f.Response == nil || f.Response.ResponseCode != dns.ResponseCodeNOERROR || len(f.Response.Answers) == 0 {
				t.Fatalf("fallback response=%+v error=%v", f.Response, f.Error)
			}
			for _, answer := range f.Response.Answers {
				ip, ok := netip.AddrFromSlice(answer.Data)
				if !ok || !ip.IsLoopback() || answer.Type != tt.typ {
					t.Fatalf("unexpected fallback answer %+v", answer)
				}
			}
		})
	}
}

func TestHostsOptionInvalidation(t *testing.T) {
	server := dnsServer(t)
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("192.0.2.99 ipv4.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := options.New()
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	r := New(opts, nil)
	r.hostsPath, r.port = path, server.Port()
	if err := manager.Add(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		return opts.Update(ctx, map[string]any{"dns_name_servers": []string{"127.0.0.1"}})
	}); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		useHosts bool
		want     string
	}{
		"hosts enabled":  {useHosts: true, want: "192.0.2.99"},
		"hosts disabled": {want: "1.2.3.4"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"dns_use_hosts_file": tt.useHosts})
			}); err != nil {
				t.Fatal(err)
			}
			f := flow.NewDNSFlow(&connection.Client{ProxyMode: "dns"}, connection.NewServer(nil), true)
			f.Request = &dns.Message{Query: true, Questions: []dns.Question{{Name: "ipv4.example.com", Type: dns.TypeA, Class: dns.ClassIN}}}
			if err := manager.Trigger(t.Context(), addon.DNSRequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if f.Response == nil || len(f.Response.Answers) != 1 {
				t.Fatalf("response=%+v", f.Response)
			}
			ip, ok := netip.AddrFromSlice(f.Response.Answers[0].Data)
			if !ok || ip.String() != tt.want {
				t.Fatalf("answer=%v, want %s", ip, tt.want)
			}
		})
	}
}

func TestForwardingQueryShapes(t *testing.T) {
	tests := map[string]struct {
		query     bool
		opcode    int
		questions []dns.Question
	}{
		"not a query":        {questions: []dns.Question{{Name: "host", Type: dns.TypeA, Class: dns.ClassIN}}},
		"other opcode":       {query: true, opcode: dns.OpCodeSTATUS, questions: []dns.Question{{Name: "host", Type: dns.TypeA, Class: dns.ClassIN}}},
		"no questions":       {query: true},
		"multiple questions": {query: true, questions: []dns.Question{{Name: "host", Type: dns.TypeA, Class: dns.ClassIN}, {Name: "host", Type: dns.TypeAAAA, Class: dns.ClassIN}}},
		"other class":        {query: true, questions: []dns.Question{{Name: "host", Type: dns.TypeA, Class: dns.ClassCH}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
			t.Cleanup(manager.Close)
			r := New(opts, nil)
			if err := manager.Add(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(context.Context) error { r.cached = &resolverConfig{servers: []string{"192.0.2.53"}}; return nil }); err != nil {
				t.Fatal(err)
			}
			f := flow.NewDNSFlow(&connection.Client{ProxyMode: "dns"}, connection.NewServer(nil), true)
			f.Request = &dns.Message{Query: tt.query, OpCode: tt.opcode, Questions: tt.questions}
			if err := manager.Trigger(t.Context(), addon.DNSRequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if f.Response != nil || f.Error != nil || f.ServerConn.Address == nil || f.ServerConn.Address.Host != "192.0.2.53" || f.ServerConn.Address.Port != 53 {
				t.Fatalf("forwarding changed flow: response=%+v error=%v address=%+v", f.Response, f.Error, f.ServerConn.Address)
			}
		})
	}
}
