// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

func TestTLSStartServerHTTP2Policy(t *testing.T) {
	tests := map[string]struct {
		disabled       bool
		offers, preset [][]byte
		want           []string
	}{
		"success: enabled preserves offer order":         {offers: bss("h2", "http/1.1", "custom"), want: []string{"h2", "http/1.1", "custom"}},
		"success: disabled removes h2":                   {disabled: true, offers: bss("h2", "http/1.1", "custom"), want: []string{"http/1.1", "custom"}},
		"success: disabled h2-only offer yields no ALPN": {disabled: true, offers: bss("h2")},
		"success: no client offers yields no ALPN":       {},
		"success: preset offers win":                     {offers: bss("h2"), preset: bss("http/1.1", "custom"), want: []string{"http/1.1", "custom"}},
		"success: preset h2 is not filtered":             {disabled: true, preset: bss("h2"), want: []string{"h2"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc, manager, opts := newTLSConfig(t)
			if err := configure(t, manager, opts, map[string]any{"http2": !tt.disabled, "ssl_insecure": true}); err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			c.Client.ALPNOffers = tt.offers
			c.Server.Address = &connection.Address{Host: "example.test", Port: 443}
			c.Server.ALPNOffers = tt.preset
			data := &hookdata.TLS{Conn: &c.Server.Connection, Context: c}
			if err := manager.Do(t.Context(), func(ctx context.Context) error { return tc.TLSStartServer(ctx, data) }); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, data.Config.NextProtos); diff != "" {
				t.Errorf("origin ALPN (-want +got):\n%s", diff)
			}
		})
	}
}
