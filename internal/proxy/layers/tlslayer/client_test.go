// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

type clientObserver struct {
	config *tls.Config
	hello  func(*hookdata.ClientHello)
	check  func(string, *hookdata.TLS)
	events []string
}

func (o *clientObserver) TLSClientHello(_ context.Context, data *hookdata.ClientHello) error {
	o.events = append(o.events, "tls_clienthello")
	if o.hello != nil {
		o.hello(data)
	}
	return nil
}

func (o *clientObserver) TLSStartClient(_ context.Context, data *hookdata.TLS) error {
	data.Config = o.config
	return o.handle("tls_start_client", data)
}

func (o *clientObserver) TLSEstablishedClient(_ context.Context, data *hookdata.TLS) error {
	return o.handle("tls_established_client", data)
}

func (o *clientObserver) TLSFailedClient(_ context.Context, data *hookdata.TLS) error {
	return o.handle("tls_failed_client", data)
}

func (o *clientObserver) handle(event string, data *hookdata.TLS) error {
	o.events = append(o.events, event)
	if o.check != nil {
		o.check(event, data)
	}
	return nil
}

func (o *clientObserver) TCPStart(context.Context, *flow.TCPFlow) error {
	o.events = append(o.events, "tcp_start")
	return nil
}

func (o *clientObserver) TCPMessage(context.Context, *flow.TCPFlow) error {
	o.events = append(o.events, "tcp_message")
	return nil
}

func (o *clientObserver) TCPError(context.Context, *flow.TCPFlow) error {
	o.events = append(o.events, "tcp_error")
	return nil
}

func (o *clientObserver) TCPEnd(context.Context, *flow.TCPFlow) error {
	o.events = append(o.events, "tcp_end")
	return nil
}

func newClientSession(t *testing.T, observer *clientObserver) *serverSession {
	t.Helper()
	s := newServerSession(t, &tlsObserver{})
	if err := s.manager.Add(t.Context(), observer); err != nil {
		t.Fatal(err)
	}
	return s
}

// The harness owns transport closure, just as the production handler does.
func startClientLayer(t *testing.T, s *serverSession, l layer.Layer) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done, finished := make(chan error, 1), make(chan struct{})
	go func() {
		err := l.Run(ctx, s.c)
		_ = s.c.Client.Close()
		done <- err
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		_ = s.c.Client.Close()
		await(t, finished)
	})
	return done
}

func lowerEcho() innerLayer {
	return innerLayer{kind: "test-lower-echo", run: func(_ context.Context, c *layer.Context) error {
		c.Client.StopRecording()
		request := make([]byte, 4)
		if _, err := io.ReadFull(c.Client, request); err != nil {
			return err
		}
		_, err := c.Client.Write(bytes.ToLower(request))
		return err
	}}
}

// Upstream TestClientTLS.test_client_only.
func TestClientTLSOnly(t *testing.T) {
	tests := map[string]struct {
		viaNext bool
		version uint16
	}{
		"explicit child": {version: tls.VersionTLS13},
		"next child":     {viaNext: true, version: tls.VersionTLS12},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			config, peerConfig := tlsConfigs(t)
			config.MinVersion, config.MaxVersion = tt.version, tt.version
			config.NextProtos, peerConfig.NextProtos = []string{"custom"}, []string{"custom"}
			observer := &clientObserver{config: config}
			observer.hello = func(data *hookdata.ClientHello) {
				if data.ClientHello == nil || data.ClientHello.SNI() != "example.com" {
					t.Errorf("ClientHello = %v", data.ClientHello)
				}
				client := data.Context.Client
				if !client.TLS || client.SNI == nil || *client.SNI != "example.com" {
					t.Errorf("hello metadata missing: TLS=%t SNI=%v", client.TLS, client.SNI)
				}
				if diff := gocmp.Diff([][]byte{[]byte("custom")}, client.ALPNOffers); diff != "" {
					t.Error(diff)
				}
				if client.TLSEstablished() || client.ALPN != nil {
					t.Error("handshake published before tls_clienthello")
				}
			}
			observer.check = func(event string, data *hookdata.TLS) {
				if !data.IsClient() || data.Config != config {
					t.Errorf("%s: incorrect target or config identity", event)
				}
				if event == "tls_established_client" && (!data.Conn.TLSEstablished() || string(data.Conn.ALPN) != "custom") {
					t.Errorf("%s: completed metadata not published", event)
				}
			}
			s := newClientSession(t, observer)
			var child layer.Layer = lowerEcho()
			if tt.viaNext {
				child = nil
				s.c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) { return lowerEcho(), nil }
			}
			done := startClientLayer(t, s, &clientTLS{child: child})
			peer := tls.Client(s.clientPeer, peerConfig)
			if err := peer.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write([]byte("PING")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 4)
			if _, err := io.ReadFull(peer, reply); err != nil || string(reply) != "ping" {
				t.Fatalf("reply = %q, %v", reply, err)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"tls_clienthello", "tls_start_client", "tls_established_client"}, observer.events); diff != "" {
				t.Error(diff)
			}
			client := s.c.Data.Client
			block, rest := pem.Decode(client.MitmCert)
			if block == nil || len(rest) != 0 || !bytes.Equal(block.Bytes, config.Certificates[0].Certificate[0]) {
				t.Error("MitmCert does not identify the certificate actually presented")
			}
			if client.Cipher == nil || client.TLSVersion != versionName(tt.version) {
				t.Errorf("completed cipher/version missing: %v, %q", client.Cipher, client.TLSVersion)
			}
			// Client-only TLS must not wrap or consume unrelated upstream data.
			if _, err := s.peer.Write([]byte("plain")); err != nil {
				t.Fatal(err)
			}
			plain := make([]byte, 5)
			if _, err := io.ReadFull(s.raw, plain); err != nil || string(plain) != "plain" {
				t.Fatalf("server bytes: %q, %v", plain, err)
			}
		})
	}
}

func TestClientTLSNilConfig(t *testing.T) {
	observer := &clientObserver{}
	s := newClientSession(t, observer)
	done := startClientLayer(t, s, &clientTLS{child: lowerEcho()})
	if _, err := s.clientPeer.Write(helloRecords(helloMessage(0), 512)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := s.clientPeer.Read(b[:]); err == nil {
		t.Fatal("client remains open after missing configuration")
	}
	if err := await(t, done); err == nil {
		t.Fatal("missing config succeeded")
	}
	if diff := gocmp.Diff([]string{"tls_clienthello", "tls_start_client"}, observer.events); diff != "" {
		t.Error(diff)
	}
	logs := s.logs.String()
	if !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, "No TLS context was provided, failing connection.") {
		t.Errorf("missing configuration log = %q", logs)
	}
}

// Upstream TestClientTLS.test_cannot_parse_clienthello.
func TestClientTLSMalformedHello(t *testing.T) {
	observer := &clientObserver{}
	s := newClientSession(t, observer)
	s.c.NextLayer = func(context.Context, *layer.Context) (layer.Layer, error) {
		t.Error("selected a child after malformed hello")
		return lowerEcho(), nil
	}
	done := startClientLayer(t, s, &clientTLS{})
	if _, err := s.peer.Write([]byte("unrelated server input")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.clientPeer.Write([]byte{0x16, 3, 3, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err == nil || !strings.Contains(err.Error(), "Cannot parse ClientHello") {
		t.Fatalf("malformed hello error = %v", err)
	}
	if diff := gocmp.Diff([]string{"tls_failed_client"}, observer.events); diff != "" {
		t.Error(diff)
	}
	if s.c.Data.Client.Error == nil || s.c.Data.Client.TLSEstablished() {
		t.Fatal("incorrect failed handshake metadata")
	}
	if logs := s.logs.String(); !strings.Contains(logs, "1603030000") {
		t.Errorf("missing bounded hex diagnostic: %q", logs)
	}
}

// Upstream TestClientTLS.test_mitmproxy_ca_is_untrusted and test_unsupported_protocol.
func TestClientTLSHandshakeFailure(t *testing.T) {
	tests := map[string]struct {
		configure func(*tls.Config, *tls.Config)
		want      string
	}{
		"untrusted proxy certificate": {configure: func(_, peer *tls.Config) { peer.ServerName = "wrong.host" }, want: "does not trust"},
		"unsupported version":         {configure: func(local, peer *tls.Config) { local.MinVersion = tls.VersionTLS13; peer.MaxVersion = tls.VersionTLS12 }, want: "TLS version"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			config, peerConfig := tlsConfigs(t)
			tt.configure(config, peerConfig)
			observer := &clientObserver{config: config, check: func(event string, data *hookdata.TLS) {
				if event == "tls_failed_client" && (data.Conn.Error == nil || data.Conn.TLSEstablished()) {
					t.Error("failure hook observes incorrect metadata")
				}
			}}
			s := newClientSession(t, observer)
			done := startClientLayer(t, s, &clientTLS{child: lowerEcho()})
			if err := tls.Client(s.clientPeer, peerConfig).HandshakeContext(t.Context()); err == nil {
				t.Fatal("peer handshake unexpectedly succeeded")
			}
			if err := await(t, done); err == nil {
				t.Fatal("proxy handshake unexpectedly succeeded")
			}
			if diff := gocmp.Diff([]string{"tls_clienthello", "tls_start_client", "tls_failed_client"}, observer.events); diff != "" {
				t.Error(diff)
			}
			if logs := s.logs.String(); !strings.Contains(logs, tt.want) {
				t.Errorf("logs = %q, want %q", logs, tt.want)
			}
		})
	}
}

// Upstream TestClientTLS.test_immediate_disconnect.
func TestClientTLSImmediateDisconnect(t *testing.T) {
	tests := map[string]struct{ at string }{
		"clienthello hook": {at: "tls_clienthello"},
		"start hook":       {at: "tls_start_client"},
		"handshake":        {at: "handshake"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			config, peerConfig := tlsConfigs(t)
			observer := &clientObserver{config: config}
			s := newClientSession(t, observer)
			observer.hello = func(*hookdata.ClientHello) {
				if tt.at == "tls_clienthello" {
					_ = s.clientPeer.Close()
				}
			}
			observer.check = func(event string, _ *hookdata.TLS) {
				if tt.at == event {
					_ = s.clientPeer.Close()
				}
			}
			if tt.at == "handshake" {
				config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { _ = s.clientPeer.Close(); return nil, nil }
			}
			done := startClientLayer(t, s, &clientTLS{child: lowerEcho()})
			_ = tls.Client(s.clientPeer, peerConfig).HandshakeContext(t.Context())
			if err := await(t, done); err == nil {
				t.Fatal("disconnected handshake succeeded")
			}
			if diff := gocmp.Diff([]string{"tls_clienthello", "tls_start_client", "tls_failed_client"}, observer.events); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClientTLSCancelHello(t *testing.T) {
	s := newClientSession(t, &clientObserver{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- (&clientTLS{}).Run(ctx, s.c) }()
	cancel()
	if err := await(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled hello read: %v", err)
	}
}

func TestClientTLSBuild(t *testing.T) {
	s := newClientSession(t, &clientObserver{})
	l, err := layer.Build(t.Context(), s.c, hookdata.LayerStack{{Kind: hookdata.LayerClientTLS}, {Kind: hookdata.LayerTCP}})
	if err != nil {
		t.Fatal(err)
	}
	if l.Kind() != hookdata.LayerClientTLS {
		t.Fatalf("Kind = %q", l.Kind())
	}
	layertest.NoDirectHooks(t)
}

func TestClientTLSConformance(t *testing.T) {
	layertest.Conformance(t, func(t *testing.T) layertest.Session {
		config, peerConfig := tlsConfigs(t)
		s := newClientSession(t, &clientObserver{config: config})
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
			done <- (&clientTLS{}).Run(ctx, s.c)
			close(finished)
		}()
		t.Cleanup(func() {
			cancel()
			_ = s.c.Client.Close()
			await(t, finished)
		})
		peer := tls.Client(s.clientPeer, peerConfig)
		if err := peer.HandshakeContext(ctx); err != nil {
			t.Fatal(err)
		}
		derived := await(t, ready)
		return layertest.Session{
			Client: peer, Server: s.peer,
			ClientInput: derived.Client, ServerInput: derived.Server,
			ClientData: []byte("request over TLS"), ServerData: []byte("response after half-close"),
			Run: func(context.Context) error {
				close(release)
				return <-done
			},
		}
	})
}
