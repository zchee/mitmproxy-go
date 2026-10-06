// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestH2CPriorKnowledgeWithoutDisableAddon(t *testing.T) {
	tests := map[string]struct{ http2 bool }{
		"success: omitted rejection addon permits cleartext h2": {http2: true},
		"error: http2 option still disables cleartext h2":       {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "origin.test" || r.URL.Path != "/cleartext" {
					t.Errorf("origin request = %s %s", r.Host, r.URL.Path)
				}
				if _, err := io.WriteString(w, "cleartext-h2"); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(origin.Close)
			p := proxytest.Start(t, proxytest.WithOrigin("origin.test", &proxytest.Origin{Addr: origin.Listener.Addr().String()}), proxytest.WithOptions(map[string]any{"http2": tt.http2, "connection_strategy": "lazy"}))
			transport := &http.Transport{Protocols: new(http.Protocols), DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, p.Addr)
			}}
			transport.Protocols.SetUnencryptedHTTP2(true)
			t.Cleanup(transport.CloseIdleConnections)
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://origin.test/cleartext", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&http.Client{Transport: transport}).Do(request)
			if !tt.http2 {
				if err == nil {
					_ = response.Body.Close()
					t.Fatal("disabled HTTP2 accepted a cleartext exchange")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.ProtoMajor != 2 || string(body) != "cleartext-h2" {
				t.Errorf("response = %s, %q", response.Proto, body)
			}
		})
	}
}
