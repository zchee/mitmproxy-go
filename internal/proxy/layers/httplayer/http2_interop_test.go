// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

// Explicit protocol overrides exercise version translation independently of
// tlsconfig's default policy of following the origin's ALPN selection.
type versionTLS struct{ client, server string }

func (v *versionTLS) TLSStartClient(_ context.Context, d *hookdata.TLS) error {
	d.Config.NextProtos = []string{v.client}
	return nil
}

func (v *versionTLS) TLSStartServer(_ context.Context, d *hookdata.TLS) error {
	d.Config.NextProtos = []string{v.server}
	return nil
}

func TestHTTPVersionInterop(t *testing.T) {
	tests := map[string]struct{ client, server int }{
		"success: h1 client and h1 origin": {client: 1, server: 1},
		"success: h1 client and h2 origin": {client: 1, server: 2},
		"success: h2 client and h1 origin": {client: 2, server: 1},
		"success: h2 client and h2 origin": {client: 2, server: 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			protocol := make(chan int, 1)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("origin body: %v", err)
					return
				}
				protocol <- r.ProtoMajor
				w.Header().Set("Trailer", "X-Final")
				w.Header().Add("X-Duplicate", "one")
				w.Header().Add("X-Duplicate", "two")
				if _, err := w.Write(body); err != nil {
					t.Errorf("origin response: %v", err)
				}
				w.Header().Set("X-Final", "last")
			}))
			origin.EnableHTTP2 = tt.server == 2
			origin.StartTLS()
			t.Cleanup(origin.Close)
			clientProtocol, serverProtocol := "http/1.1", "http/1.1"
			if tt.client == 2 {
				clientProtocol = "h2"
			}
			if tt.server == 2 {
				serverProtocol = "h2"
			}
			p := proxytest.Start(t,
				proxytest.WithOrigin("versions.test", &proxytest.Origin{Addr: origin.Listener.Addr().String(), CA: origin.Certificate()}),
				proxytest.WithOptions(map[string]any{"ssl_insecure": true}),
				proxytest.WithAddons(&versionTLS{client: clientProtocol, server: serverProtocol}),
			)
			raw, err := net.Dial("tcp4", p.Addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = raw.Close() })
			if err := raw.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprint(raw, "CONNECT versions.test:443 HTTP/1.1\r\nHost: versions.test:443\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			connect, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"})
			if err != nil {
				t.Fatal(err)
			}
			if connect.StatusCode != 200 {
				t.Fatalf("CONNECT status = %d", connect.StatusCode)
			}
			if err := connect.Body.Close(); err != nil {
				t.Fatal(err)
			}
			conn := tls.Client(raw, &tls.Config{RootCAs: p.CAPool, ServerName: "versions.test", NextProtos: []string{clientProtocol}})
			if err := conn.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := conn.ConnectionState().NegotiatedProtocol; got != clientProtocol {
				t.Fatalf("client ALPN = %q, want %q", got, clientProtocol)
			}
			request, err := http.NewRequestWithContext(t.Context(), "POST", "https://versions.test/echo", bytes.NewBufferString("request-body"))
			if err != nil {
				t.Fatal(err)
			}
			var response *http.Response
			if tt.client == 2 {
				protocols := new(http.Protocols)
				protocols.SetHTTP2(true)
				transport := &http.Transport{Protocols: protocols, DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}
				client, connectErr := transport.NewClientConn(t.Context(), "https", "versions.test:443")
				if connectErr != nil {
					t.Fatal(connectErr)
				}
				t.Cleanup(func() { _ = client.Close() })
				response, err = client.RoundTrip(request)
			} else {
				if err := request.Write(conn); err != nil {
					t.Fatal(err)
				}
				response, err = http.ReadResponse(bufio.NewReader(conn), request)
			}
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("request-body", string(body)); diff != "" {
				t.Errorf("body (-want +got):\n%s", diff)
			}
			if response.StatusCode != 200 || response.ProtoMajor != tt.client {
				t.Fatalf("response = %d %s; body = %q", response.StatusCode, response.Proto, body)
			}
			if got := <-protocol; got != tt.server {
				t.Errorf("origin protocol = HTTP/%d, want HTTP/%d", got, tt.server)
			}
			if diff := gocmp.Diff([]string{"one", "two"}, response.Header.Values("X-Duplicate")); diff != "" {
				t.Errorf("duplicate headers (-want +got):\n%s", diff)
			}
			if got := response.Trailer.Get("X-Final"); got != "last" {
				t.Errorf("trailer = %q", got)
			}
		})
	}
}
