// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func awaitHTTP2[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(30 * time.Second):
		stack := make([]byte, 1<<20)
		t.Fatalf("HTTP/2 hang detector expired\n%s", stack[:runtime.Stack(stack, true)])
	}
	var zero T
	return zero
}

func nativeHTTP2Client(t *testing.T, p *proxytest.Proxy) *http.ClientConn {
	t.Helper()
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
	response, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{RootCAs: p.CAPool, ServerName: "versions.test", NextProtos: []string{"h2", "http/1.1"}})
	if err := conn.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("ALPN = %q, want h2", got)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{Protocols: protocols, DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}
	client, err := transport.NewClientConn(t.Context(), "https", "versions.test:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

type interceptedHTTP2 struct{ paused chan *flow.HTTPFlow }

func (a *interceptedHTTP2) RequestHeaders(_ context.Context, f *flow.HTTPFlow) error {
	if f.Request.Path == "/paused" {
		f.Intercept()
		a.paused <- f
	}
	return nil
}

func TestHTTP2InterceptedStreamIsolation(t *testing.T) {
	tests := map[string]struct{ cancel, h2Origin bool }{
		"success: paused stream and h2 sibling":           {h2Origin: true},
		"success: paused stream and separate h1 origin":   {},
		"success: cancelled paused stream and h2 sibling": {cancel: true, h2Origin: true},
		"success: cancelled paused stream and h1 sibling": {cancel: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.WriteString(w, r.URL.Path); err != nil {
					t.Error(err)
				}
			}))
			origin.EnableHTTP2 = tt.h2Origin
			origin.StartTLS()
			t.Cleanup(origin.Close)
			interceptor := &interceptedHTTP2{paused: make(chan *flow.HTTPFlow, 1)}
			protocol := "http/1.1"
			if tt.h2Origin {
				protocol = "h2"
			}
			p := proxytest.Start(t,
				proxytest.WithOrigin("versions.test", &proxytest.Origin{Addr: origin.Listener.Addr().String(), CA: origin.Certificate()}),
				proxytest.WithOptions(map[string]any{"ssl_insecure": true}),
				proxytest.WithAddons(&versionTLS{client: "h2", server: protocol}, interceptor),
			)
			client := nativeHTTP2Client(t, p)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			first, err := http.NewRequestWithContext(ctx, "GET", "https://versions.test/paused", nil)
			if err != nil {
				t.Fatal(err)
			}
			completed := make(chan error, 1)
			go func() {
				response, err := client.RoundTrip(first)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					err = errors.Join(err, response.Body.Close())
				}
				completed <- err
			}()
			paused := awaitHTTP2(t, interceptor.paused)
			if tt.cancel {
				cancel()
				if err := awaitHTTP2(t, completed); err == nil {
					t.Fatal("cancelled stream succeeded")
				}
			}
			request, err := http.NewRequestWithContext(t.Context(), "GET", "https://versions.test/other", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.RoundTrip(request)
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
			if response.StatusCode != 200 || string(body) != "/other" {
				t.Fatalf("sibling response = %d %q", response.StatusCode, body)
			}
			if !tt.cancel {
				if err := p.Master.Do(t.Context(), func(context.Context) error { paused.Resume(); return nil }); err != nil {
					t.Fatal(err)
				}
				if err := awaitHTTP2(t, completed); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
