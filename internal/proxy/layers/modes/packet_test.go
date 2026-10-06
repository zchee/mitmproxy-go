// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes_test

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

func TestReversePacketDestination(t *testing.T) {
	tests := map[string]struct {
		scheme  string
		keep    bool
		wantSNI string
	}{
		"UDP":                 {scheme: "udp", wantSNI: "original.test"},
		"DTLS":                {scheme: "dtls", wantSNI: "origin.test"},
		"DTLS preserves host": {scheme: "dtls", keep: true, wantSNI: "original.test"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := newContext(t, "reverse:"+test.scheme+"://origin.test:8443@127.0.0.1:0")
			c.Data.Client.TransportProtocol = connection.UDP
			c.Data.Server.SNI = new("original.test")
			if err := c.Data.Options.Update(t.Context(), map[string]any{"keep_host_header": test.keep}); err != nil {
				t.Fatal(err)
			}
			build(t, c, hookdata.LayerReverse)
			if diff := gocmp.Diff(&connection.Address{Host: "origin.test", Port: 8443}, c.Data.Server.Address); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(new(test.wantSNI), c.Data.Server.SNI); diff != "" {
				t.Fatal(diff)
			}
			if c.Data.Server.TransportProtocol != connection.UDP {
				t.Fatal("reverse packet origin has stream metadata")
			}
		})
	}
}
