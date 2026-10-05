// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"crypto/tls"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestServerSetup(t *testing.T) {
	tests := map[string]struct{ decorated bool }{
		"direct origin":             {},
		"already wrapped by parent": {decorated: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConfig, clientConfig := tlsConfigs(t)
			target := connection.NewServer(nil)
			observer := &tlsObserver{config: clientConfig, check: func(event string, data *hookdata.TLS) {
				if data.Conn != &target.Connection || !data.IsServer() || !data.Conn.TLS {
					t.Errorf("%s: incorrect server setup target", event)
				}
			}}
			s := newServerSession(t, observer)
			peer := pongPeer(t, s.peer, serverConfig)
			var pool layer.ServerPool = s.pool
			if tt.decorated {
				pool = &serverTLSPool{inner: pool, c: s.c}
			}
			conn, actual, err := pool.Open(t.Context(), target, layer.OpenOptions{Setup: ServerSetup(s.c)})
			if err != nil {
				t.Fatal(err)
			}
			if actual != target {
				t.Fatal("pool changed target identity")
			}
			if err := pingPong(conn); err != nil {
				t.Fatal(err)
			}
			if err := await(t, peer); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"tls_start_server", "tls_established_server"}, observer.events); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestServerSetupNestedTarget(t *testing.T) {
	serverConfig, clientConfig := tlsConfigs(t)
	s := newServerSession(t, &tlsObserver{config: clientConfig})
	proxyTarget, originTarget := connection.NewServer(nil), connection.NewServer(nil)
	peer := make(chan error, 1)
	go func() {
		outer := &tlsConn{Conn: tls.Server(s.peer, serverConfig), raw: s.peer}
		if err := outer.HandshakeContext(t.Context()); err != nil {
			peer <- err
			return
		}
		peer <- <-pongPeer(t, outer, serverConfig)
	}()
	setup := ServerSetup(s.c)
	conn, _, err := s.pool.Open(t.Context(), proxyTarget, layer.OpenOptions{Setup: func(ctx context.Context, raw layer.Conn, actual *connection.Server) (layer.Conn, error) {
		outer, err := setup(ctx, raw, actual)
		if err != nil {
			return nil, err
		}
		return setup(ctx, outer, originTarget)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := pingPong(conn); err != nil {
		t.Fatal(err)
	}
	if err := await(t, peer); err != nil {
		t.Fatal(err)
	}
	want := []string{"tls_start_server", "tls_established_server", "tls_start_server", "tls_established_server"}
	if diff := gocmp.Diff(want, s.observed.events); diff != "" {
		t.Error(diff)
	}
}
