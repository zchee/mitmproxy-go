// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"bytes"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

const dtlsHello = "16fefd00000000000000000085" + "010000790000000000000079" +
	"fefd62bf0e0bf809df43e7669197be831919878b1a72c07a584d3c0a8ca6665878010000000cc02bc02fc00ac014c02cc0" +
	"3001000043000d0010000e0403050306030401050106010807ff01000100000a00080006001d00170018000b00020100001" +
	"7000000000010000e00000b6578616d706c652e636f6d"

func TestPacketNextLayerUpstream(t *testing.T) {
	encrypted := hello(t, dtlsHello)
	udp, clientDTLS, serverDTLS := hookdata.LayerUDP, hookdata.LayerClientDTLS, hookdata.LayerServerDTLS
	tests := map[string]struct {
		mode, host       string
		data             []byte
		ignore, udpHosts []string
		sni              string
		want             hookdata.LayerStack
	}{
		"reverse proxy: udp -> udp":    {mode: "reverse:udp://example.com:42", want: hookdata.LayerStack{{Kind: udp}}},
		"reverse proxy: dtls -> dtls":  {mode: "reverse:dtls://example.com:42", data: encrypted, want: hookdata.LayerStack{{Kind: serverDTLS}, {Kind: clientDTLS}, {Kind: udp}}},
		"reverse proxy: dtls -> udp":   {mode: "reverse:udp://example.com:42", data: encrypted, want: hookdata.LayerStack{{Kind: clientDTLS}, {Kind: udp}}},
		"reverse proxy: udp -> dtls":   {mode: "reverse:dtls://example.com:42", want: hookdata.LayerStack{{Kind: serverDTLS}, {Kind: udp}}},
		"transparent proxy: dtls":      {data: encrypted, want: hookdata.LayerStack{{Kind: serverDTLS}, {Kind: clientDTLS}}},
		"transparent proxy: raw udp":   {host: "192.0.2.1", data: []byte{0xff}, want: hookdata.LayerStack{{Kind: udp}}},
		"transparent proxy: udp_hosts": {host: "192.0.2.1", data: []byte{0xff}, udpHosts: []string{"192.0.2.1"}, want: hookdata.LayerStack{{Kind: udp}}},
		"udp_hosts matches SNI":        {host: "192.0.2.1", sni: "example.com", udpHosts: []string{"EXAMPLE.COM"}, want: hookdata.LayerStack{{Kind: udp}}},
		"ignore UDP":                   {host: "example.com", ignore: []string{"example.com"}, want: hookdata.LayerStack{{Kind: udp, Ignore: true}}},
		"HTTP-looking UDP is raw":      {host: "192.0.2.1", data: []byte("GET / HTTP/1.1"), ignore: []string{"example.com"}, want: hookdata.LayerStack{{Kind: udp}}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, map[string]any{"ignore_hosts": test.ignore, "udp_hosts": test.udpHosts})
			kind := hookdata.LayerKind("transparent")
			if test.mode != "" {
				kind = hookdata.LayerReverse
			}
			c := testContext(a.opts, test.host, kind)
			c.Client.TransportProtocol, c.Server.TransportProtocol = connection.UDP, connection.UDP
			c.Client.ProxyMode = test.mode
			if test.sni != "" {
				c.Client.SNI = new(test.sni)
			}
			d := &hookdata.NextLayer{Context: c, DataClient: test.data}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, d.Layer); diff != "" {
				t.Fatalf("stack (-upstream +go):\n%s", diff)
			}
		})
	}
}

func TestPacketIgnoreClientHelloUpstream(t *testing.T) {
	complete := hello(t, dtlsHello)
	tests := map[string]struct {
		data              []byte
		ignored, deferred bool
	}{
		"dtls sni":                     {data: complete, ignored: true},
		"incomplete dtls client hello": {data: complete[:len(complete)-5], deferred: true},
		"invalid dtls client hello":    {data: append(bytes.Clone(complete[:9]), make([]byte, 200)...)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, map[string]any{"ignore_hosts": []string{"example.com"}})
			c := testContext(a.opts, "192.0.2.1", "transparent")
			c.Client.TransportProtocol, c.Server.TransportProtocol = connection.UDP, connection.UDP
			d := &hookdata.NextLayer{Context: c, DataClient: test.data}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if test.deferred {
				if d.Layer != nil {
					t.Fatalf("incomplete input chose %v", d.Layer)
				}
				return
			}
			if d.Layer == nil {
				t.Fatal("complete input deferred")
			}
			got := d.Layer[0].Kind == hookdata.LayerUDP && d.Layer[0].Ignore
			if diff := gocmp.Diff(test.ignored, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestPacketSniffLimit(t *testing.T) {
	a, manager, logs := testAddon(t, nil)
	c := testContext(a.opts, "example.com", "transparent")
	c.Client.TransportProtocol, c.Server.TransportProtocol = connection.UDP, connection.UDP
	d := &hookdata.NextLayer{Context: c, DataClient: bytes.Repeat([]byte{'x'}, sniffLimit)}
	if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(hookdata.LayerStack{{Kind: hookdata.LayerUDP}}, d.Layer); diff != "" {
		t.Fatal(diff)
	}
	if !strings.Contains(logs.String(), "falling back to raw UDP") {
		t.Fatalf("missing UDP warning: %s", logs.String())
	}
}
