// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/options"
)

func TestReverseSchemeMetadata(t *testing.T) {
	tests := map[string]struct {
		client connection.TransportProtocol
		server connection.TransportProtocol
		kind   hookdata.LayerKind
		secure bool
		eager  bool
	}{
		"http":  {connection.TCP, connection.TCP, hookdata.LayerHTTP, false, true},
		"https": {connection.TCP, connection.TCP, hookdata.LayerHTTP, true, true},
		"tls":   {connection.TCP, connection.TCP, hookdata.LayerTCP, true, true},
		"tcp":   {connection.TCP, connection.TCP, hookdata.LayerTCP, false, true},
		"udp":   {connection.UDP, connection.UDP, hookdata.LayerUDP, false, false},
		"dtls":  {connection.UDP, connection.UDP, hookdata.LayerUDP, true, false},
		"dns":   {connection.UDP, connection.UDP, "dns", false, false},
		"quic":  {connection.UDP, connection.UDP, "quic", true, false},
		"http3": {connection.UDP, connection.UDP, hookdata.LayerHTTP, true, false},
	}
	for scheme, tt := range tests {
		t.Run(scheme, func(t *testing.T) {
			opts := options.New()
			if err := opts.Add(t.Context(), "keep_host_header", options.TypeBool, false, "Preserve host."); err != nil {
				t.Fatal(err)
			}
			if err := opts.Add(t.Context(), "connection_strategy", options.TypeStr, "eager", "Connect strategy."); err != nil {
				t.Fatal(err)
			}
			client := connection.NewClient(connection.Address{}, connection.Address{}, 1)
			client.ProxyMode = "reverse:" + scheme + "://example.test:443"
			client.TransportProtocol = tt.client
			c := &layer.Context{Data: &hookdata.Context{Client: client, Server: connection.NewServer(nil), Options: opts}}
			entry, err := configureReverse(c)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.server, c.Data.Server.TransportProtocol); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(tt.kind, entry.application); diff != "" {
				t.Fatal(diff)
			}
			if got := entry.connectEagerly(c); got != tt.eager {
				t.Fatalf("eager=%v, want %v", got, tt.eager)
			}
			var wantSNI *string
			if tt.secure {
				wantSNI = new("example.test")
			}
			if diff := gocmp.Diff(wantSNI, c.Data.Server.SNI); diff != "" {
				t.Fatal(diff)
			}
			if err := opts.Update(t.Context(), map[string]any{"keep_host_header": true}); err != nil {
				t.Fatal(err)
			}
			c.Data.Server.SNI = new("original.test")
			if _, err := configureReverse(c); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(new("original.test"), c.Data.Server.SNI); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
