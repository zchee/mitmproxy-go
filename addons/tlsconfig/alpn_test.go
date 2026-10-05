// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func bss(ss ...string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = []byte(s)
	}
	return out
}

// Upstream test_alpn_select_callback, plus one row per remaining branch of
// the selection rule.
func TestALPNSelect(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		clientALPN []byte
		serverALPN []byte
		offers     [][]byte
		http2      bool
		want       []byte
	}{
		"success: preset from an addon wins": {
			clientALPN: []byte("qux"), serverALPN: []byte("h2"), http2: true,
			offers: bss("http/1.1", "qux", "h2"), want: []byte("qux"),
		},
		"success: empty preset selects nothing": {
			clientALPN: []byte{}, serverALPN: []byte("h2"), http2: true,
			offers: bss("http/1.1", "qux", "h2"), want: nil,
		},
		"success: preset not offered selects nothing": {
			clientALPN: []byte("spdy/3"), http2: true,
			offers: bss("http/1.1"), want: nil,
		},
		"success: server protocol is mirrored": {
			serverALPN: []byte("h2"), http2: true,
			offers: bss("http/1.1", "qux", "h2"), want: []byte("h2"),
		},
		"success: client preference among http protocols": {
			http2:  true,
			offers: bss("qux", "http/1.1", "h2"), want: []byte("http/1.1"),
		},
		"success: h2 wins when preferred and enabled": {
			http2:  true,
			offers: bss("qux", "h2", "http/1.1"), want: []byte("h2"),
		},
		"success: h2 skipped when disabled": {
			offers: bss("qux", "h2", "http/1.1"), want: []byte("http/1.1"),
		},
		"success: no overlap selects nothing": {
			http2:  true,
			offers: bss("qux", "quux"), want: nil,
		},
		"success: server refusal is mirrored": {
			serverALPN: []byte{}, http2: true,
			offers: bss("http/1.1"), want: nil,
		},
		"success: no offers selects nothing": {
			http2: true, want: nil,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := alpnSelect(tt.clientALPN, tt.serverALPN, tt.offers, tt.http2)
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("alpnSelect mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Upstream TestTlsConfig.test_alpn_selection: the offers sent to the server
// mirror the client's offers, without h2 when http2 is off.
func TestServerALPNOffers(t *testing.T) {
	t.Parallel()
	all := bss("h2", "http/1.1", "http/1.0", "http/0.9", "foo")
	tests := map[string]struct {
		clientOffers [][]byte
		http2        bool
		want         [][]byte
	}{
		"success: http2 on keeps every offer":   {clientOffers: all, http2: true, want: all},
		"success: http2 off drops h2":           {clientOffers: all, want: bss("http/1.1", "http/1.0", "http/0.9", "foo")},
		"success: no offers with http2 on":      {http2: true, want: nil},
		"success: no offers with http2 off":     {want: nil},
		"success: h2 only with http2 off":       {clientOffers: bss("h2"), want: nil},
		"success: offers without h2 stay equal": {clientOffers: bss("http/1.1"), want: bss("http/1.1")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := serverALPNOffers(tt.clientOffers, tt.http2)
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("serverALPNOffers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
