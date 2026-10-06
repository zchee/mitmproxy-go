// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
	"github.com/zchee/mitmproxy-go/options"
)

// The upstream upgrade and prior-knowledge cases in test_disable_h2c.py are
// exercised here through the actual default addon set and connection handler.
func TestDefaultAddonsRefuseH2C(t *testing.T) {
	tests := map[string]struct {
		request string
		upgrade bool
	}{
		"success: upgrade stripped before reaching origin": {request: "GET / HTTP/1.1\r\nHost: origin.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABk\r\n\r\n", upgrade: true},
		"success: prior knowledge killed without dialing":  {request: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			originHead := make(chan http.Header, 1)
			origin := proxytest.StartOrigin(t, func(conn net.Conn) {
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = request.Body.Close() }()
				originHead <- request.Header
				if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
					t.Error(err)
				}
			})
			opts := options.New()
			if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir(), "server": false}); err != nil {
				t.Fatal(err)
			}
			m, err := dump.New(t.Context(), dump.Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
					t.Error(err)
				}
			})
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"connection_strategy": "lazy"})
			}); err != nil {
				t.Fatal(err)
			}
			if m.Addons.Get("disableh2c") == nil {
				t.Fatal("default addon set is missing disableh2c")
			}
			var dials atomic.Int32
			dial := proxy.NewDialer(net.Dialer{})
			handler, err := proxy.NewHandler(proxy.Config{
				Manager: m.Addons, Options: opts, Connections: new(proxy.Connections), Logger: m.Logger(),
				Dialer: func(ctx context.Context, srv *connection.Server) (layer.Conn, error) {
					dials.Add(1)
					return dial(ctx, srv)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			client, accepted := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = accepted.Close() })
			if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- handler.Handle(t.Context(), accepted, "reverse:http://"+origin.Addr, hookdata.LayerSpec{Kind: hookdata.LayerReverse})
			}()
			if _, err := io.WriteString(client, tt.request); err != nil {
				t.Fatal(err)
			}
			if tt.upgrade {
				response, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if diff := cmp.Diff(http.StatusOK, response.StatusCode); diff != "" {
					t.Fatal(diff)
				}
				head := <-originHead
				for _, key := range []string{"Upgrade", "Connection", "HTTP2-Settings"} {
					if value := head.Get(key); value != "" {
						t.Errorf("origin received %s: %q", key, value)
					}
				}
			} else if data, err := io.ReadAll(client); err != nil || len(data) != 0 {
				t.Fatalf("prior knowledge returned %q, error %v; want a closed connection", data, err)
			}
			select {
			case err := <-done:
				if err != nil && !strings.Contains(err.Error(), "Connection killed") {
					t.Fatal(err)
				}
			case <-time.After(30 * time.Second):
				stacks := make([]byte, 1<<20)
				t.Fatalf("handler did not clean up\n%s", stacks[:runtime.Stack(stacks, true)])
			}
			wantDials := int32(0)
			if tt.upgrade {
				wantDials = 1
			}
			if diff := cmp.Diff(wantDials, dials.Load()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
