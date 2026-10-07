// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func dnsServer(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			request, err := dns.Unpack(buffer[:n], nil)
			if err != nil {
				t.Error(err)
				return
			}
			question, ok := request.Question()
			if !ok {
				t.Error("server received multiple questions")
				return
			}
			var response *dns.Message
			switch question.Name {
			case "ipv4.example.com", "ipv6.example.com":
				answers := []dns.ResourceRecord{}
				if question.Name == "ipv4.example.com" && question.Type == dns.TypeA {
					answers = append(answers, dns.A(question.Name, netip.MustParseAddr("1.2.3.4"), 86400))
				} else if question.Name == "ipv6.example.com" && question.Type == dns.TypeAAAA {
					answers = append(answers, dns.AAAA(question.Name, netip.IPv6Loopback(), 86400))
				}
				response = request.Succeed(answers)
			case "no-a-records.example.com":
				response = request.Succeed(nil)
			case "no-network.example.com":
				response, err = request.Fail(dns.ResponseCodeSERVFAIL)
			default:
				response, err = request.Fail(dns.ResponseCodeNXDOMAIN)
			}
			if err != nil {
				t.Error(err)
				return
			}
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
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestDNSRequest(t *testing.T) {
	server := dnsServer(t)
	noDataCode := dns.ResponseCodeNOERROR
	// Windows aliases EAI_NODATA to EAI_NONAME: test_dns_resolver.py:129-134.
	if runtime.GOOS == "windows" {
		noDataCode = dns.ResponseCodeNXDOMAIN
	}
	tests := map[string]struct {
		name     string
		typ      int
		code     int
		ip       string
		forward  bool
		useHosts bool
	}{
		"ipv4":              {name: "ipv4.example.com", typ: dns.TypeA, ip: "1.2.3.4"},
		"ipv6":              {name: "ipv6.example.com", typ: dns.TypeAAAA, ip: "::1"},
		"nxdomain":          {name: "nxdomain.example.com", typ: dns.TypeA, code: dns.ResponseCodeNXDOMAIN},
		"no data":           {name: "no-a-records.example.com", typ: dns.TypeA, code: noDataCode},
		"failure":           {name: "no-network.example.com", typ: dns.TypeA, code: dns.ResponseCodeSERVFAIL},
		"forward TXT":       {name: "txt.example.com", typ: dns.TypeTXT, forward: true},
		"ipv4 hosts":        {name: "ipv4.example.com", typ: dns.TypeA, ip: "1.2.3.4", useHosts: true},
		"ipv6 hosts":        {name: "ipv6.example.com", typ: dns.TypeAAAA, ip: "::1", useHosts: true},
		"nxdomain hosts":    {name: "nxdomain.example.com", typ: dns.TypeA, code: dns.ResponseCodeNXDOMAIN, useHosts: true},
		"no data hosts":     {name: "no-a-records.example.com", typ: dns.TypeA, code: noDataCode, useHosts: true},
		"failure hosts":     {name: "no-network.example.com", typ: dns.TypeA, code: dns.ResponseCodeSERVFAIL, useHosts: true},
		"forward TXT hosts": {name: "txt.example.com", typ: dns.TypeTXT, forward: true, useHosts: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			cmds := command.NewManager()
			manager := addon.NewManager(opts, cmds, addon.Config{})
			t.Cleanup(manager.Close)
			r := New(opts, nil)
			r.port = server.Port()
			r.hostsPath = filepath.Join(t.TempDir(), "hosts")
			if err := manager.Add(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"dns_name_servers": []string{"127.0.0.1"}, "dns_use_hosts_file": tt.useHosts})
			}); err != nil {
				t.Fatal(err)
			}
			f := flow.NewDNSFlow(&connection.Client{ProxyMode: "dns"}, connection.NewServer(nil), true)
			f.Request = &dns.Message{ID: 42, Query: true, RecursionDesired: true, Questions: []dns.Question{{Name: tt.name, Type: tt.typ, Class: dns.ClassIN}}}
			if err := manager.Trigger(t.Context(), addon.DNSRequestHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if f.Error != nil {
				t.Fatal(f.Error)
			}
			if tt.forward {
				if diff := gocmp.Diff(&connection.Address{Host: "127.0.0.1", Port: 53}, f.ServerConn.Address); diff != "" {
					t.Fatal(diff)
				}
				if f.Response != nil {
					t.Fatal("forwarded query was answered")
				}
				return
			}
			if f.Response == nil {
				t.Fatal("missing response")
			}
			if f.Response.ResponseCode != tt.code {
				t.Fatalf("response code = %d, want %d", f.Response.ResponseCode, tt.code)
			}
			if tt.ip == "" {
				if len(f.Response.Answers) != 0 {
					t.Fatal("unexpected answers")
				}
			} else {
				if len(f.Response.Answers) != 1 {
					t.Fatalf("answers = %+v", f.Response.Answers)
				}
				got, ok := netip.AddrFromSlice(f.Response.Answers[0].Data)
				if !ok || got.String() != tt.ip {
					t.Fatalf("address = %v, want %s", got, tt.ip)
				}
				if f.Response.Answers[0].TTL != dns.DefaultTTL {
					t.Fatal("resolver did not use upstream default TTL")
				}
			}
		})
	}
}
