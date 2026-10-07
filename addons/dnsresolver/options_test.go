// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestOptions(t *testing.T) {
	opts := options.NewManager()
	cmds := command.NewManager()
	manager := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), New(opts, nil)); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{
		"dns_use_hosts_file": {typ: options.TypeBool, def: true, help: "Use the hosts file for DNS lookups in regular DNS mode/wireguard mode."},
		"dns_name_servers":   {typ: options.TypeSeq, def: []string{}, help: "Name servers to use for lookups in regular DNS mode/wireguard mode. Default: operating system's name servers"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			option, ok := opts.Lookup(name)
			if !ok {
				t.Fatal("missing option")
			}
			if option.Type() != tt.typ || option.Help() != tt.help {
				t.Fatalf("option type/help = %v, %q", option.Type(), option.Help())
			}
			if diff := gocmp.Diff(tt.def, option.Default()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	if len(opts.Keys()) != len(tests) {
		t.Fatalf("unexpected option set: %v", opts.Keys())
	}
	for name := range cmds.Commands() {
		t.Fatalf("unexpected command: %s", name)
	}
}

func TestShouldResolve(t *testing.T) {
	// Ports test_dns_resolver.py::test_ignores_reverse_mode and its guard.
	tests := map[string]struct {
		mode     string
		address  *connection.Address
		live     bool
		response bool
		failed   bool
		want     bool
	}{
		"dns":             {mode: "dns", live: true, want: true},
		"dns override":    {mode: "dns@127.0.0.1:5300", live: true, want: true},
		"wireguard DNS":   {mode: "wireguard", address: &connection.Address{Host: "10.0.0.53", Port: 53}, live: true, want: true},
		"wireguard other": {mode: "wireguard", address: &connection.Address{Host: "1.1.1.1", Port: 53}, live: true},
		"reverse DNS":     {mode: "reverse:dns://8.8.8.8", live: true},
		"not live":        {mode: "dns"},
		"answered":        {mode: "dns", live: true, response: true},
		"failed":          {mode: "dns", live: true, failed: true},
		"unknown":         {mode: "bad", live: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := flow.NewDNSFlow(&connection.Client{ProxyMode: tt.mode}, connection.NewServer(tt.address), tt.live)
			if tt.response {
				f.Response = &dns.Message{}
			}
			if tt.failed {
				f.Error = flow.NewError("failed")
			}
			if got := shouldResolve(f); got != tt.want {
				t.Fatalf("shouldResolve = %v, want %v", got, tt.want)
			}
		})
	}
}
