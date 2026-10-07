// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestResolverFiles(t *testing.T) {
	tests := map[string]struct {
		text string
		want resolvConfig
	}{
		"nameservers":          {text: "nameserver 127.0.0.1 # loopback\nnameserver ::1\nnameserver invalid\n", want: resolvConfig{servers: []string{"127.0.0.1", "::1"}}},
		"inert system options": {text: "search example.com corp.example\ndomain last.example\noptions ndots:2\n", want: resolvConfig{}},
		"duplicates":           {text: "nameserver ::1\nnameserver ::1\n", want: resolvConfig{servers: []string{"::1"}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			if err := os.WriteFile(path, []byte(tt.text), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := readResolvConf(path)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got, gocmp.AllowUnexported(resolvConfig{})); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestHostsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	text := "1.2.3.4 Example.COM Alias # comment\n::1 example.com\ninvalid ignored\n1.2.3.4 example.com\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := readHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]netip.Addr{"example.com": {netip.MustParseAddr("1.2.3.4"), netip.IPv6Loopback()}, "alias": {netip.MustParseAddr("1.2.3.4")}}
	if diff := gocmp.Diff(want, hosts, gocmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
		t.Fatal(diff)
	}
	cfg := resolverConfig{hosts: hosts, useHosts: true}
	for _, typ := range []int{1, 28} {
		ips, err := cfg.lookup(t.Context(), "EXAMPLE.COM.", typ)
		if err != nil || len(ips) != 1 {
			t.Fatalf("hosts lookup %d = %v, %v", typ, ips, err)
		}
	}
}

func TestResolverFileLimits(t *testing.T) {
	tests := map[string]struct{ text string }{
		"oversized": {text: strings.Repeat("# line\n", 180000)},
		"long line": {text: strings.Repeat("x", (1<<20)+1)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oversized")
			if err := os.WriteFile(path, []byte(tt.text), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readHosts(path); err == nil {
				t.Fatal("oversized hosts accepted")
			}
			if _, err := readResolvConf(path); err == nil {
				t.Fatal("oversized resolver configuration accepted")
			}
		})
	}
}

func TestResolverFileBoundary(t *testing.T) {
	tests := map[string]struct{ newline bool }{
		"unterminated": {},
		"terminated":   {newline: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			text := "#" + strings.Repeat("x", (1<<20)-1)
			if tt.newline {
				text = text[:len(text)-1] + "\n"
			}
			path := filepath.Join(t.TempDir(), "boundary")
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readHosts(path); err != nil {
				t.Fatalf("legal hosts file rejected: %v", err)
			}
			if _, err := readResolvConf(path); err != nil {
				t.Fatalf("legal resolver configuration rejected: %v", err)
			}
		})
	}
}

func TestInterleave(t *testing.T) {
	// These orderings come from src/dns.rs::interleave_inplace tests.
	tests := map[string]struct {
		input []bool
		want  []bool
	}{
		"more ipv4": {input: []bool{false, true, false, true, true}, want: []bool{true, false, true, false, true}},
		"more ipv6": {input: []bool{false, false, false, true}, want: []bool{true, false, false, false}},
		"ipv4 only": {input: []bool{true, true, true}, want: []bool{true, true, true}},
		"ipv6 only": {input: []bool{false, false}, want: []bool{false, false}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addresses := make([]netip.Addr, len(tt.input))
			for i, is4 := range tt.input {
				if is4 {
					addresses[i] = netip.IPv4Unspecified()
				} else {
					addresses[i] = netip.IPv6Unspecified()
				}
			}
			interleave(addresses)
			got := make([]bool, len(addresses))
			for i, ip := range addresses {
				got[i] = ip.Is4()
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
