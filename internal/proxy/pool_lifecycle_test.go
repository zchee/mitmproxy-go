// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestPoolShutdownInterruptsSetup(t *testing.T) {
	tests := map[string]struct{ upgrade bool }{
		"initial setup": {},
		"upgrade":       {upgrade: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dialer := &poolDialer{t: t}
			recorder := &addontest.Recorder{}
			pool, _ := newPool(t, dialer.dial, recorder)
			srv := targetServer()
			entered := make(chan struct{})
			setup := func(_ context.Context, conn layer.Conn, _ *connection.Server) (layer.Conn, error) {
				close(entered)
				var buf [1]byte
				_, err := conn.Read(buf[:])
				return nil, err
			}
			done := make(chan openResult, 1)
			if tt.upgrade {
				_, actual, err := pool.Open(t.Context(), srv, layer.OpenOptions{})
				if err != nil {
					t.Fatal(err)
				}
				go func() {
					conn, actual, err := pool.Upgrade(t.Context(), actual, setup)
					done <- openResult{conn, actual, err}
				}()
			} else {
				go func() {
					conn, actual, err := pool.Open(t.Context(), srv, layer.OpenOptions{Setup: setup})
					done <- openResult{conn, actual, err}
				}()
			}
			await(t, entered)
			closed := make(chan error, 1)
			go func() { closed <- pool.closeAll(t.Context()) }()
			if err := await(t, closed); err != nil {
				t.Fatal(err)
			}
			if result := await(t, done); result.err == nil || result.conn != nil {
				t.Fatalf("setup survived shutdown: %+v", result)
			}
			if diff := gocmp.Diff([]string{"server_connect", "server_connected", "server_disconnected"}, serverHooks(recorder)); diff != "" {
				t.Fatalf("shutdown hooks (-want +got):\n%s", diff)
			}
			if _, ok := pool.Lookup(srv); ok {
				t.Fatal("shutdown pool exposed a transport")
			}
		})
	}
}

func TestPoolUpgradeFailureCached(t *testing.T) {
	dialer := &poolDialer{t: t}
	recorder := &addontest.Recorder{}
	pool, _ := newPool(t, dialer.dial, recorder)
	_, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("upstream handshake rejected")
	setup := func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error) { return nil, failure }
	if _, _, err := pool.Upgrade(t.Context(), srv, setup); !errors.Is(err, failure) {
		t.Fatalf("Upgrade error = %v, want %v", err, failure)
	}
	if srv.Error == nil || *srv.Error != failure.Error() {
		t.Fatalf("cached server error = %v", srv.Error)
	}
	if _, _, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{Reuse: true}); !errors.Is(err, failure) {
		t.Fatalf("cached Open error = %v", err)
	}
	if _, _, err := pool.Upgrade(t.Context(), srv, setup); !errors.Is(err, failure) {
		t.Fatalf("cached Upgrade error = %v", err)
	}
	if _, ok := pool.Lookup(srv); ok {
		t.Fatal("failed upgrade remained available")
	}
	if _, err := dialer.peer(0).Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("failed upgrade did not close the socket: %v", err)
	}
	if _, fresh, err := pool.Open(t.Context(), srv, layer.OpenOptions{}); err != nil || fresh == srv || fresh.ID == srv.ID {
		t.Fatalf("fresh retry = (%v, %v)", fresh, err)
	}
}

func TestPoolRealHalfClose(t *testing.T) {
	tests := map[string]struct{ peerFirst bool }{
		"peer closes first":  {peerFirst: true},
		"proxy closes first": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			raw, peer := layertest.Pipe(t)
			recorder := &addontest.Recorder{}
			pool, _ := newPool(t, func(context.Context, *connection.Server) (layer.Conn, error) { return raw, nil }, recorder)
			conn, srv, err := pool.Open(t.Context(), targetServer(), layer.OpenOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if tt.peerFirst {
				if err := peer.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				requireReplay(t, conn, []byte{})
				if srv.State != connection.CanWrite {
					t.Fatalf("state = %v, want can-write", srv.State)
				}
				written := make(chan error, 1)
				go func() {
					_, err := conn.Write([]byte("reply"))
					written <- errors.Join(err, conn.CloseWrite())
				}()
				requireReplay(t, peer, []byte("reply"))
				if err := await(t, written); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				requireReplay(t, peer, []byte{})
				if srv.State != connection.CanRead {
					t.Fatalf("state = %v, want can-read", srv.State)
				}
				written := make(chan error, 1)
				go func() {
					_, err := peer.Write([]byte("reply"))
					written <- errors.Join(err, peer.CloseWrite())
				}()
				requireReplay(t, conn, []byte("reply"))
				if err := await(t, written); err != nil {
					t.Fatal(err)
				}
			}
			if srv.State != connection.Closed || srv.TimestampEnd == nil {
				t.Fatalf("fully closed server = %v", srv)
			}
			if diff := gocmp.Diff([]string{"server_connect", "server_connected", "server_disconnected"}, serverHooks(recorder)); diff != "" {
				t.Fatalf("half-close hooks (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPoolKeys(t *testing.T) {
	tests := map[string]struct{ change func(*connection.Server) }{
		"host":      {func(srv *connection.Server) { srv.Address.Host = "other.test" }},
		"port":      {func(srv *connection.Server) { srv.Address.Port++ }},
		"tls":       {func(srv *connection.Server) { srv.TLS = true }},
		"transport": {func(srv *connection.Server) { srv.TransportProtocol = connection.UDP }},
		"sni":       {func(srv *connection.Server) { sni := "other.test"; srv.SNI = &sni }},
		"empty sni": {func(srv *connection.Server) { sni := ""; srv.SNI = &sni }},
		"scope":     {func(srv *connection.Server) { srv.Address.Scope = &connection.IPv6Scope{ScopeID: 1} }},
		"via": {func(srv *connection.Server) {
			srv.Via = &connection.ServerSpec{Scheme: "http", Address: connection.Address{Host: "proxy.test", Port: 8080}}
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dialer := &poolDialer{t: t}
			pool, _ := newPool(t, dialer.dial)
			base := targetServer()
			first, _, err := pool.Open(t.Context(), base, layer.OpenOptions{Reuse: true})
			if err != nil {
				t.Fatal(err)
			}
			changed := targetServer()
			tt.change(changed)
			second, _, err := pool.Open(t.Context(), changed, layer.OpenOptions{Reuse: true})
			if err != nil || second == first || dialer.count() != 2 {
				t.Fatalf("different key reused: conn %v, error %v, dials %d", second, err, dialer.count())
			}
			if conn, _, err := pool.Open(t.Context(), changed.Clone(), layer.OpenOptions{Reuse: true}); err != nil || conn != second {
				t.Fatalf("equal key did not reuse: conn %v, error %v", conn, err)
			}
		})
	}
}
