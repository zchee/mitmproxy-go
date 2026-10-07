// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

// Upstream test_next_layer DNS cases and protocol/host precedence.
func TestDNSSelection(t *testing.T) {
	dnsStack := hookdata.LayerStack{{Kind: "dns"}}
	tests := map[string]struct {
		udp              bool
		port             int
		mode, alpn       string
		ignore, rawHosts []string
		data             []byte
		want             hookdata.LayerStack
	}{
		"transparent DNS TCP":                       {port: 53, want: dnsStack},
		"transparent DNS UDP":                       {udp: true, port: 53, want: dnsStack},
		"multicast DNS TCP":                         {port: 5353, want: dnsStack},
		"multicast DNS UDP":                         {udp: true, port: 5353, want: dnsStack},
		"wireguard DNS remains inspectable":         {udp: true, port: 53, mode: "wireguard", want: dnsStack},
		"reverse DNS ignores destination port":      {udp: true, port: 443, mode: "reverse:dns://example.test:443", want: dnsStack},
		"reverse DNS TCP ignores TLS-looking bytes": {port: 443, mode: "reverse:dns://example.test:443", data: []byte{0x16, 0x03, 0x03, 0, 0}, want: dnsStack},
		"TCP host rule precedes DNS":                {port: 53, rawHosts: []string{"example.test"}, want: hookdata.LayerStack{{Kind: hookdata.LayerTCP}}},
		"UDP host rule precedes DNS":                {udp: true, port: 53, rawHosts: []string{"example.test"}, want: hookdata.LayerStack{{Kind: hookdata.LayerUDP}}},
		"ignore rule precedes DNS":                  {udp: true, port: 53, ignore: []string{"example.test"}, want: hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: true}}},
		"HTTP ALPN precedes DNS":                    {port: 53, alpn: "h2", want: hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}},
		"TLS precedes port DNS":                     {port: 53, data: []byte{0x16, 0x03, 0x03, 0, 0}, want: hookdata.LayerStack{{Kind: hookdata.LayerServerTLS}, {Kind: hookdata.LayerClientTLS}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rawOption := "tcp_hosts"
			if tt.udp {
				rawOption = "udp_hosts"
			}
			a, manager, _ := testAddon(t, map[string]any{rawOption: tt.rawHosts, "ignore_hosts": tt.ignore})
			top := hookdata.LayerKind("transparent")
			if tt.mode == "wireguard" {
				top = "wireguard"
			} else if tt.mode != "" {
				top = hookdata.LayerReverse
			}
			c := testContext(a.opts, "example.test", top)
			c.Server.Address.Port = tt.port
			c.Client.ALPN = []byte(tt.alpn)
			c.Client.ProxyMode = tt.mode
			if tt.udp {
				c.Client.TransportProtocol, c.Server.TransportProtocol = connection.UDP, connection.UDP
			}
			d := &hookdata.NextLayer{Context: c, DataClient: tt.data}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, d.Layer); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
