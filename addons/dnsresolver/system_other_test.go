// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package dnsresolver

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestNameServers(t *testing.T) {
	tests := map[string]struct {
		config   string
		explicit []string
		missing  bool
		want     string
	}{
		"system":            {config: "nameserver 192.0.2.53\nnameserver 192.0.2.54\n", want: "192.0.2.53"},
		"explicit override": {config: "nameserver 192.0.2.53\n", explicit: []string{"192.0.2.55"}, want: "192.0.2.55"},
		"unknown servers":   {missing: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			if !tt.missing {
				if err := os.WriteFile(path, []byte(tt.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			opts := options.New()
			manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
			t.Cleanup(manager.Close)
			r := New(opts, slog.New(slog.NewTextHandler(&logs, nil)))
			r.resolvPath = path
			if err := manager.Add(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"dns_name_servers": tt.explicit, "dns_use_hosts_file": false})
			}); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				f := flow.NewDNSFlow(&connection.Client{ProxyMode: "dns"}, connection.NewServer(nil), true)
				f.Request = &dns.Message{Query: true, Questions: []dns.Question{{Name: "host", Type: dns.TypeTXT, Class: dns.ClassIN}}}
				if err := manager.Trigger(t.Context(), addon.DNSRequestHook{Flow: f}); err != nil {
					t.Fatal(err)
				}
				if tt.missing {
					if f.Error == nil || f.Error.Msg != "Cannot resolve, dns_name_servers unknown." {
						t.Fatalf("missing-server error=%v", f.Error)
					}
				} else if f.ServerConn.Address == nil || f.ServerConn.Address.Host != tt.want {
					t.Fatalf("forwarding server=%+v, want %s", f.ServerConn.Address, tt.want)
				}
			}
			if tt.missing && strings.Count(logs.String(), "Failed to get system dns servers") != 1 {
				t.Fatalf("system configuration warning not cached: %s", logs.String())
			}
		})
	}
}
