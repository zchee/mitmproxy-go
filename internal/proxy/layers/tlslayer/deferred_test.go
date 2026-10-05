// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

// A pre-open server transport whose direct child terminates client TLS is
// upgraded on the child's first use of the server, never before, and later
// opens take the pool's ordinary path.
func TestServerTLSDeferredUpgrade(t *testing.T) {
	serverConfig, clientConfig := tlsConfigs(t)
	config, peerConfig := tlsConfigs(t)
	observer := &clientObserver{config: config}
	s := newClientSession(t, observer)
	s.observed.config = clientConfig
	s.c.Server = proxy.Record(s.raw)
	firstPeer := pongPeer(t, s.peer, serverConfig)
	raw2, peer2 := layertest.Pipe(t)
	secondPeer := pongPeer(t, peer2, serverConfig)
	inner := innerLayer{kind: "test-deferred-open", run: func(ctx context.Context, c *layer.Context) error {
		if c.Server != nil {
			return errors.New("deferred raw transport visible to the child")
		}
		if err := c.Do(ctx, func(context.Context) error {
			if len(s.observed.events) != 0 {
				return fmt.Errorf("server TLS started before first use: %v", s.observed.events)
			}
			return nil
		}); err != nil {
			return err
		}
		conn, err := openServer(ctx, c)
		if err != nil {
			return err
		}
		if err := pingPong(conn); err != nil {
			return err
		}
		var metadata *connection.Server
		if err := c.Do(ctx, func(context.Context) error {
			metadata = c.Data.Server
			return nil
		}); err != nil {
			return err
		}
		reused, actual, err := c.Pool.Open(ctx, metadata, layer.OpenOptions{Reuse: true})
		if err != nil {
			return err
		}
		if reused != conn || actual != metadata || s.pool.setups != 1 {
			return fmt.Errorf("reuse replaced the upgraded transport or repeated setup: same=%t, actual=%t, setups=%d", reused == conn, actual == metadata, s.pool.setups)
		}
		// A later non-reusing open takes the pool's ordinary path and wraps
		// the new transport in its own TLS session.
		s.pool.conn = raw2
		second, err := openServer(ctx, c)
		if err != nil {
			return err
		}
		return pingPong(second)
	}}
	done := startClientLayer(t, s, &serverTLS{child: &clientTLS{child: inner}})
	peer := tls.Client(s.clientPeer, peerConfig)
	if err := peer.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if err := await(t, firstPeer); err != nil {
		t.Fatal(err)
	}
	if err := await(t, secondPeer); err != nil {
		t.Fatal(err)
	}
	want := []string{"tls_start_server", "tls_established_server", "tls_start_server", "tls_established_server"}
	if diff := gocmp.Diff(want, s.observed.events); diff != "" {
		t.Error(diff)
	}
	if s.pool.setups != 2 {
		t.Errorf("pool setups = %d, want 2", s.pool.setups)
	}
}

// A fatal TLS record error after the established hook surfaces through the
// relay like upstream's post-handshake failures: the `TLS Error: ...` log,
// no second TLS failure hook, and that direction's close.
func TestServerTLSPostHandshakeRecordError(t *testing.T) {
	serverConfig, clientConfig := tlsConfigs(t)
	sequence := make(chan string, 16)
	tcpObserver := &clientObserver{tcpEnd: func() { sequence <- "tcp_end" }}
	s := newClientSession(t, tcpObserver)
	s.observed.config = clientConfig
	s.observed.check = func(event string, _ *hookdata.TLS) { sequence <- event }
	s.c.Logger = slog.New(slog.NewTextHandler(s.logs, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.MessageKey && strings.HasPrefix(attr.Value.String(), "TLS Error:") {
				sequence <- "TLS Error"
			}
			return attr
		},
	}))
	s.c.Server = proxy.Record(s.raw)
	l, err := layer.Build(t.Context(), s.c, hookdata.LayerStack{{Kind: hookdata.LayerServerTLS}, {Kind: hookdata.LayerTCP}})
	if err != nil {
		t.Fatal(err)
	}
	peer := make(chan error, 1)
	go func() {
		tc := tls.Server(s.peer, serverConfig)
		if err := tc.HandshakeContext(t.Context()); err != nil {
			peer <- err
			return
		}
		// A record longer than TLS permits is a fatal post-handshake error.
		_, err := s.peer.Write([]byte{0x17, 0x03, 0x03, 0xff, 0xff})
		peer <- err
	}()
	done := startClientLayer(t, s, l)
	if err := await(t, peer); err != nil {
		t.Fatal(err)
	}
	forwarded, err := io.ReadAll(s.clientPeer)
	if err != nil || len(forwarded) != 0 {
		t.Fatalf("client observed %q, %v after the server record error", forwarded, err)
	}
	sequence <- "client_eof"
	if err := s.clientPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// The failed read closes that direction; TCP drains the other direction
	// and emits tcp_end, not tcp_error or a second TLS failure hook.
	if err := await(t, done); err != nil {
		t.Fatalf("relay did not treat the record error as a close: %v", err)
	}
	close(sequence)
	var observed []string
	for event := range sequence {
		observed = append(observed, event)
	}
	want := []string{"tls_start_server", "tls_established_server", "TLS Error", "client_eof", "tcp_end"}
	if diff := gocmp.Diff(want, observed); diff != "" {
		t.Errorf("post-handshake event ordering (-want +got):\n%s", diff)
	}
	if diff := gocmp.Diff([]string{"tls_start_server", "tls_established_server"}, s.observed.events); diff != "" {
		t.Error(diff)
	}
	if diff := gocmp.Diff([]string{"tcp_start", "tcp_end"}, tcpObserver.events); diff != "" {
		t.Error(diff)
	}
	if logs := s.logs.String(); !strings.Contains(logs, "TLS Error:") {
		t.Errorf("missing post-handshake diagnostic: %q", logs)
	}
}

// A handler shutdown during the client handshake returns the context's
// error without firing failure hooks nobody observes.
func TestClientTLSCancelHandshake(t *testing.T) {
	config, _ := tlsConfigs(t)
	observer := &clientObserver{config: config}
	s := newClientSession(t, observer)
	ctx, cancel := context.WithCancel(t.Context())
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cancel()
		return nil, nil
	}
	done, finished := make(chan error, 1), make(chan struct{})
	go func() {
		done <- (&clientTLS{child: lowerEcho()}).Run(ctx, s.c)
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		_ = s.c.Client.Close()
		await(t, finished)
	})
	if _, err := s.clientPeer.Write(helloRecords(helloMessage(0), 512)); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled handshake returned %v", err)
	}
	if diff := gocmp.Diff([]string{"tls_clienthello", "tls_start_client"}, observer.events); diff != "" {
		t.Error(diff)
	}
}
