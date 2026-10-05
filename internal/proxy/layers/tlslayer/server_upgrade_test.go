// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"crypto/tls"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestServerReplayUsesBufferedBytesOnly(t *testing.T) {
	tests := map[string]struct {
		consumed int
	}{
		"success: peeked bytes":   {},
		"success: consumed bytes": {consumed: 5},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			old, oldPeer := layertest.Pipe(t)
			recorded := proxy.Record(old)
			const prefix = "recorded-prefix"
			if _, err := oldPeer.Write([]byte(prefix)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(recorded, make([]byte, tt.consumed)); err != nil {
				t.Fatal(err)
			}
			if _, err := recorded.Peek(len(prefix) - tt.consumed); err != nil {
				t.Fatal(err)
			}
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			current, peer := layertest.Pipe(t)
			conn := replayServer(recorded, current)
			if _, err := peer.Write([]byte("current-suffix")); err != nil {
				t.Fatal(err)
			}
			want := prefix + "current-suffix"
			got := make([]byte, len(want))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(want, string(got)); diff != "" {
				t.Fatalf("replayed bytes (-want +got):\n%s", diff)
			}
			if _, err := conn.Write([]byte("write-current")); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			written, err := io.ReadAll(peer)
			if err != nil || string(written) != "write-current" {
				t.Fatalf("current transport received %q, %v", written, err)
			}
		})
	}
}

// The callback's transport may be the inner tunnel of a pooled wrapper. TLS
// must not capture the old wrapper which the upgrade will subsequently replace.
func TestServerTLSUpgradeUsesCallbackTransport(t *testing.T) {
	tests := map[string]struct {
		deferred    bool
		serverFirst bool
	}{
		"success: eager":                 {},
		"success: deferred client first": {deferred: true},
		"success: deferred server first": {deferred: true, serverFirst: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConfig, clientConfig := tlsConfigs(t)
			inboundConfig, peerConfig := tlsConfigs(t)
			observer := &clientObserver{config: inboundConfig, hello: func(data *hookdata.ClientHello) {
				data.EstablishServerTLSFirst = tt.serverFirst
			}}
			s := newClientSession(t, observer)
			s.observed.config = clientConfig
			s.c.Server = proxy.Record(s.raw)
			// A closed original transport makes accidental reuse fail immediately,
			// while the pool supplies a separate live socket for the handshake.
			if err := s.raw.Close(); err != nil {
				t.Fatal(err)
			}
			raw, peer := layertest.Pipe(t)
			s.pool.conn = raw
			serverDone := pongPeer(t, peer, serverConfig)
			t.Cleanup(func() {
				_ = raw.Close()
				if err := await(t, serverDone); err != nil && !t.Failed() {
					t.Error(err)
				}
			})
			var child layer.Layer = innerLayer{kind: "test-callback-transport", run: func(ctx context.Context, c *layer.Context) error {
				if c.Server != nil {
					c.Server.StopRecording()
					return pingPong(c.Server)
				}
				conn, err := openServer(ctx, c)
				if err != nil {
					return err
				}
				return pingPong(conn)
			}}
			if tt.deferred {
				child = &clientTLS{child: child}
			}
			done := startClientLayer(t, s, &serverTLS{child: child})
			if tt.deferred {
				if err := tls.Client(s.clientPeer, peerConfig).HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			if s.pool.setups != 1 {
				t.Fatalf("setups = %d, want one logical upgrade", s.pool.setups)
			}
		})
	}
}
