// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestServerTLSRecordedResponse(t *testing.T) {
	_, config := tlsConfigs(t)
	s := newServerSession(t, &tlsObserver{config: config})
	s.c.Server = proxy.Record(s.raw)
	const response = "HTTP/1.1 400 Bad Request\r\n\r\n"
	if _, err := io.WriteString(s.peer, response); err != nil {
		t.Fatal(err)
	}
	if err := s.peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, len(response))
	if _, err := io.ReadFull(s.c.Server, prefix); err != nil {
		t.Fatal(err)
	}
	err := s.run(t, innerLayer{kind: "test-unused", run: func(context.Context, *layer.Context) error {
		t.Error("child ran after invalid server handshake")
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "The remote server does not speak TLS.") {
		t.Fatalf("recorded response not replayed to TLS: %v", err)
	}
}

func TestServerTLSPolicyAndSetupOrder(t *testing.T) {
	serverConfig, clientConfig := tlsConfigs(t)
	clientConfig.MinVersion, clientConfig.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	clientConfig.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	clientConfig.NextProtos = []string{"custom"}
	serverConfig.NextProtos = []string{"custom"}
	var order []string
	clientConfig.VerifyConnection = func(state tls.ConnectionState) error {
		order = append(order, "verify")
		if state.Version != tls.VersionTLS12 || state.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 || state.NegotiatedProtocol != "custom" {
			t.Errorf("hook policy not honored: version=%#x suite=%#x alpn=%q", state.Version, state.CipherSuite, state.NegotiatedProtocol)
		}
		return nil
	}
	s := newServerSession(t, &tlsObserver{config: clientConfig})
	s.pool.beforeSetup = func(_ context.Context, conn layer.Conn) error {
		order = append(order, "outer setup")
		_, err := io.WriteString(conn, "tunnel\n")
		return err
	}
	s.observed.check = func(event string, data *hookdata.TLS) {
		order = append(order, event)
		if data.Config != clientConfig {
			t.Error("TLS hook does not retain the supplied config")
		}
		if event == "tls_start_server" {
			data.Conn.SNI = new("addon-selected-name")
			data.Conn.ALPNOffers = [][]byte{[]byte("addon-selected-offer")}
		}
	}
	peer := make(chan error, 1)
	go func() {
		prefix := make([]byte, len("tunnel\n"))
		if _, err := io.ReadFull(s.peer, prefix); err != nil {
			peer <- err
			return
		}
		if string(prefix) != "tunnel\n" {
			peer <- errors.New("TLS preceded outer transport setup")
			return
		}
		peer <- <-pongPeer(t, s.peer, serverConfig)
	}()
	err := s.run(t, innerLayer{kind: "test-inner-setup", run: func(ctx context.Context, c *layer.Context) error {
		var metadata *connection.Server
		if err := c.Do(ctx, func(context.Context) error {
			metadata = c.Data.Server
			return nil
		}); err != nil {
			return err
		}
		_, _, err := c.Pool.Open(ctx, metadata, layer.OpenOptions{Setup: func(_ context.Context, conn layer.Conn, _ *connection.Server) (layer.Conn, error) {
			order = append(order, "inner setup")
			return conn, pingPong(conn)
		}})
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := await(t, peer); err != nil {
		t.Fatal(err)
	}
	want := []string{"outer setup", "tls_start_server", "verify", "tls_established_server", "inner setup"}
	if diff := gocmp.Diff(want, order); diff != "" {
		t.Errorf("setup order (-want +got):\n%s", diff)
	}
	metadata := s.server(t)
	if metadata.SNI == nil || *metadata.SNI != "addon-selected-name" {
		t.Errorf("hook-selected SNI overwritten: %v", metadata.SNI)
	}
	if diff := gocmp.Diff([][]byte{[]byte("addon-selected-offer")}, metadata.ALPNOffers); diff != "" {
		t.Errorf("hook-selected offers overwritten (-want +got):\n%s", diff)
	}
}

func TestServerTLSConformance(t *testing.T) {
	layertest.Conformance(t, func(t *testing.T) layertest.Session {
		serverConfig, clientConfig := tlsConfigs(t)
		s := newServerSession(t, &tlsObserver{config: clientConfig})
		s.c.Server = proxy.Record(s.raw)
		ready := make(chan *layer.Context, 1)
		release := make(chan struct{})
		s.c.NextLayer = func(ctx context.Context, c *layer.Context) (layer.Layer, error) {
			ready <- c
			select {
			case <-release:
				return layer.Build(ctx, c, hookdata.LayerStack{{Kind: hookdata.LayerTCP}})
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		done, finished := make(chan error, 1), make(chan struct{})
		go func() {
			done <- (&serverTLS{}).Run(ctx, s.c)
			close(finished)
		}()
		t.Cleanup(func() {
			cancel()
			await(t, finished)
		})
		peer := &tlsConn{Conn: tls.Server(s.peer, serverConfig), raw: s.peer}
		if err := peer.HandshakeContext(ctx); err != nil {
			t.Fatal(err)
		}
		derived := await(t, ready)
		return layertest.Session{
			Client: s.clientPeer, Server: peer,
			ClientInput: derived.Client, ServerInput: derived.Server,
			ClientData: []byte("request over TLS"), ServerData: []byte("response after half-close"),
			Run: func(context.Context) error {
				close(release)
				return <-done
			},
		}
	})
}
