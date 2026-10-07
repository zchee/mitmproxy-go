// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"context"
	"net"
	"net/netip"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/dns"
)

func TestSystemFallbackAddressFamilies(t *testing.T) {
	address, _ := authoritativeServer(t, false, func(request *dns.Message) *dns.Message {
		question, _ := request.Question()
		if question.Type == dns.TypeA {
			return request.Succeed([]dns.ResourceRecord{dns.A(question.Name, netip.MustParseAddr("192.0.2.42"), 60)})
		}
		return request.Succeed([]dns.ResourceRecord{dns.AAAA(question.Name, netip.MustParseAddr("2001:db8::42"), 60)})
	})
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address.String())
		},
	}
	t.Cleanup(func() { net.DefaultResolver = previous })
	tests := map[string]struct {
		typ  int
		want string
	}{
		"IPv4": {typ: dns.TypeA, want: "192.0.2.42"},
		"IPv6": {typ: dns.TypeAAAA, want: "2001:db8::42"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := resolverConfig{useHosts: true}
			got, err := cfg.lookup(t.Context(), "dnsresolver-fallback.example.invalid.", tt.typ)
			if err != nil {
				t.Fatal(err)
			}
			want := []netip.Addr{netip.MustParseAddr(tt.want)}
			if diff := gocmp.Diff(want, got, gocmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
