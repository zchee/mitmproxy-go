// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package nextlayer

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
)

func TestHTTPHostSniffing(t *testing.T) {
	tests := map[string]struct {
		data, pattern string
		ignored       bool
	}{
		"success: ASCII case insensitive":               {data: "gEt / htTp/1.1\r\nhOsT: EXAMPLE.COM\r\n\r\n", pattern: "^example.com:443$", ignored: true},
		"success: port preserved":                       {data: "GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n", pattern: "^example.com:8443$", ignored: true},
		"success: Unicode decimal port preserved":       {data: "GET / HTTP/1.1\r\nHost: example.com:４４３\r\n\r\n", pattern: "^example.com:４４３$", ignored: true},
		"success: header whitespace trimmed":            {data: "GET / HTTP/1.1\r\nHost:\t example.com \t\r\n\r\n", pattern: "^example.com:443$", ignored: true},
		"success: header terminator comes first":        {data: "GET / HTTP/1.1\r\n\r\nHost: example.com\r\n", pattern: "example.com"},
		"success: no whitespace is not a sniffed host":  {data: "GET / HTTP/1.1\r\nHost:example.com\r\n\r\n", pattern: "example.com"},
		"success: byte header case folding stays ASCII": {data: "GET / HTTP/1.1\r\nHoſt: example.com\r\n\r\n", pattern: "example.com"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, manager, _ := testAddon(t, map[string]any{"ignore_hosts": []string{tt.pattern}})
			d := &hookdata.NextLayer{Context: testContext(a.opts, "192.0.2.1", "transparent"), DataClient: []byte(tt.data)}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			want := hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}
			if tt.ignored {
				want = hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: true}}
			}
			if diff := gocmp.Diff(want, d.Layer); diff != "" {
				t.Errorf("host sniff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHTTPALPN(t *testing.T) {
	tests := map[string]struct{}{"h2": {}, "http/1.1": {}, "http/1.0": {}, "http/0.9": {}}
	for alpn := range tests {
		t.Run(alpn, func(t *testing.T) {
			a, manager, _ := testAddon(t, nil)
			c := testContext(a.opts, "example.com", "transparent")
			c.Client.ALPN = []byte(alpn)
			d := &hookdata.NextLayer{Context: c, DataClient: []byte{0xff}}
			if err := manager.Hook(t.Context(), addon.NextLayerHook{Data: d}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}, d.Layer); diff != "" {
				t.Errorf("ALPN decision (-want +got):\n%s", diff)
			}
		})
	}
}
