// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

func quicInitialFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../tlsparse/testdata/quic/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestQUICNextLayer(t *testing.T) {
	// py:mitmproxy/addons/next_layer.py:_get_client_hello and _next_layer
	// parse concatenated datagrams before evaluating ignore/allow host policy.
	first := quicInitialFixture(t, "quic_go_initial_1")
	second := quicInitialFixture(t, "quic_go_initial_2")
	complete := append(bytes.Clone(first), second...)
	tests := map[string]struct {
		mode          string
		data          []byte
		ignore, allow []string
		want          hookdata.LayerStack
	}{
		"success: QUIC header selects QUIC":       {data: complete, want: hookdata.LayerStack{{Kind: "quic"}}},
		"success: reverse QUIC":                   {mode: "reverse:quic://192.0.2.1:443", data: complete, want: hookdata.LayerStack{{Kind: "quic"}}},
		"success: incomplete Initial waits":       {data: first},
		"success: ignore SNI after both Initials": {data: complete, ignore: []string{"two-datagram\\.example"}, want: hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: true}}},
		"success: allow SNI after both Initials":  {data: complete, allow: []string{"two-datagram\\.example"}, want: hookdata.LayerStack{{Kind: "quic"}}},
		"success: allow policy waits for SNI":     {data: first, allow: []string{"two-datagram\\.example"}},
		"success: ignore origin destination":      {data: complete, ignore: []string{"192\\.0\\.2\\.1"}, want: hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: true}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, map[string]any{"ignore_hosts": tt.ignore, "allow_hosts": tt.allow})
			kind := hookdata.LayerKind("transparent")
			if tt.mode != "" {
				kind = hookdata.LayerReverse
			}
			c := testContext(a.opts, "192.0.2.1", kind)
			c.Client.TransportProtocol, c.Server.TransportProtocol = connection.UDP, connection.UDP
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

func TestQUICConcatenatedInitials(t *testing.T) {
	first := quicInitialFixture(t, "quic_go_initial_1")
	second := quicInitialFixture(t, "quic_go_initial_2")
	tests := map[string]struct{ data []byte }{
		"success: cumulative data in arrival order": {data: append(bytes.Clone(first), second...)},
		"success: cumulative data reversed":         {data: append(bytes.Clone(second), first...)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var parser tlsparse.QUICClientHelloParser
			hello, err := parser.Feed(tt.data)
			if err != nil || hello == nil || hello.SNI() != "two-datagram.example" {
				t.Fatalf("concatenated Initials = (%v, %v), want two-datagram.example", hello, err)
			}
		})
	}
}
