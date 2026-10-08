// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"bytes"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

func TestQUICNextLayerHTTP3(t *testing.T) {
	// py:mitmproxy/addons/next_layer.py:356-360,398-405 forces QUIC on
	// reverse HTTPS over UDP and keeps reverse QUIC raw.
	first := quicInitialFixture(t, "quic_go_initial_1")
	h3 := append(bytes.Clone(first), quicInitialFixture(t, "quic_go_initial_2")...)
	nonHTTP3 := quicInitialFixture(t, "rfc9001_client_initial")
	tests := map[string]struct {
		mode     string
		protocol connection.TransportProtocol
		data     []byte
		want     hookdata.LayerStack
	}{
		"success: reverse HTTP3 over UDP":                   {mode: "reverse:http3://192.0.2.1:443", protocol: connection.UDP, data: h3, want: hookdata.LayerStack{{Kind: hookdata.LayerHTTP3}}},
		"success: reverse HTTP3 without initial data":       {mode: "reverse:http3://192.0.2.1:443", protocol: connection.UDP, want: hookdata.LayerStack{{Kind: hookdata.LayerHTTP3}}},
		"success: reverse HTTP3 selection over TCP":         {mode: "reverse:http3://192.0.2.1:443", protocol: connection.TCP, data: []byte("hello"), want: hookdata.LayerStack{{Kind: hookdata.LayerHTTP3}}},
		"success: UDP reverse HTTPS with HTTP3 ALPN":        {mode: "reverse:https://192.0.2.1:443", protocol: connection.UDP, data: h3, want: hookdata.LayerStack{{Kind: hookdata.LayerHTTP3}}},
		"success: UDP reverse HTTPS without HTTP3 ALPN":     {mode: "reverse:https://192.0.2.1:443", protocol: connection.UDP, data: nonHTTP3, want: hookdata.LayerStack{{Kind: "quic"}}},
		"success: UDP reverse HTTPS always selects QUIC":    {mode: "reverse:https://192.0.2.1:443", protocol: connection.UDP, data: []byte("hello"), want: hookdata.LayerStack{{Kind: "quic"}}},
		"success: reverse QUIC remains raw with HTTP3 ALPN": {mode: "reverse:quic://192.0.2.1:443", protocol: connection.UDP, data: h3, want: hookdata.LayerStack{{Kind: "quic"}}},
		"success: non-HTTP3 QUIC remains raw":               {protocol: connection.UDP, data: nonHTTP3, want: hookdata.LayerStack{{Kind: "quic"}}},
		"success: incomplete HTTP3 Initial waits":           {mode: "reverse:https://192.0.2.1:443", protocol: connection.UDP, data: first},
		"success: TCP reverse HTTPS preserves byte TLS":     {mode: "reverse:https://192.0.2.1:443", protocol: connection.TCP, data: []byte("GET / HTTP/1.1\r\n\r\n"), want: hookdata.LayerStack{{Kind: hookdata.LayerServerTLS}, {Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, nil)
			kind := hookdata.LayerKind("transparent")
			if tt.mode != "" {
				kind = hookdata.LayerReverse
			}
			c := testContext(a.opts, "192.0.2.1", kind)
			c.Client.TransportProtocol, c.Server.TransportProtocol = tt.protocol, tt.protocol
			c.Client.ProxyMode = tt.mode
			d := &hookdata.NextLayer{Context: c, DataClient: tt.data}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, d.Layer); diff != "" {
				t.Fatalf("stack (-want +got):\n%s", diff)
			}
		})
	}
}
