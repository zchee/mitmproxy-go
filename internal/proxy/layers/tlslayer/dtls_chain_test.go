// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

type dtlsTestTransport struct {
	net.PacketConn
	ctx    context.Context
	cancel context.CancelFunc
	peer   net.Addr
}

func (c *dtlsTestTransport) Context() context.Context { return c.ctx }
func (c *dtlsTestTransport) RemoteAddr() net.Addr     { return c.peer }

// WriteTo implements the same fixed-peer contract as the origin packet dialer.
func (c *dtlsTestTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr != nil && (addr.Network() != c.peer.Network() || addr.String() != c.peer.String()) {
		return 0, errors.New("packet peer differs from fixed origin")
	}
	return c.PacketConn.WriteTo(p, c.peer)
}

func (c *dtlsTestTransport) Close() error {
	c.cancel()
	return c.PacketConn.Close()
}

func dtlsOriginTransport(t *testing.T, peer net.Addr) layer.PacketTransport {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	conn := &dtlsTestTransport{PacketConn: socket, ctx: ctx, cancel: cancel, peer: peer}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestDTLSInterceptPacketChain(t *testing.T) {
	tests := map[string]struct {
		serverFirst bool
		preopened   bool
		noSNI       bool
	}{
		"success: eager server after ClientHello": {serverFirst: true},
		"success: lazy server after client":       {},
		"success: defer preopened eager server":   {serverFirst: true, preopened: true},
		"success: defer preopened lazy server":    {preopened: true},
		"success: no client SNI":                  {serverFirst: true, noSNI: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			serverTLSConfig, clientTLSConfig := tlsConfigs(t)
			originSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			origin := packettransport.NewListener(ctx, originSocket)
			t.Cleanup(func() { _ = origin.Close() })
			originDone := make(chan error, 1)
			go func() {
				tuple, err := origin.Accept(ctx)
				if err != nil {
					originDone <- err
					return
				}
				session, err := dtls.Server(tuple, tuple.RemoteAddr(), &dtls.Config{Certificates: serverTLSConfig.Certificates, SupportedProtocols: []string{"custom"}}) //nolint:staticcheck // Exercise the frozen packet constructor.
				if err != nil {
					originDone <- err
					return
				}
				t.Cleanup(func() { _ = session.Close() })
				if err := session.HandshakeContext(ctx); err != nil {
					originDone <- err
					return
				}
				_ = session.SetDeadline(time.Now().Add(30 * time.Second))
				buf := make([]byte, 256)
				for range 100 {
					n, err := session.Read(buf)
					if err == nil {
						_, err = session.Write(buf[:n])
					}
					if err != nil {
						originDone <- err
						return
					}
				}
				originDone <- nil
			}()
			proxySocket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener := packettransport.NewListener(ctx, proxySocket)
			t.Cleanup(func() { _ = listener.Close() })
			peerSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peerSocket.Close() })
			serverName := clientTLSConfig.ServerName
			if tt.noSNI {
				serverName = ""
			}
			peer, err := dtls.Client(peerSocket, listener.LocalAddr(), &dtls.Config{RootCAs: clientTLSConfig.RootCAs, ServerName: serverName, SupportedProtocols: []string{"custom"}}) //nolint:staticcheck // Exercise the frozen packet constructor.
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			peerDone := make(chan error, 1)
			go func() { peerDone <- peer.HandshakeContext(ctx) }()
			tuple, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			s := newServerSession(t, &tlsObserver{})
			observer := &dtlsObserver{}
			observer.hello = func(d *hookdata.ClientHello) {
				wantSNI := "example.com"
				if tt.noSNI {
					wantSNI = ""
				}
				if !d.ClientHello.IsDTLS() || d.ClientHello.SNI() != wantSNI {
					t.Errorf("ClientHello SNI = %q, DTLS = %v", d.ClientHello.SNI(), d.ClientHello.IsDTLS())
				}
				d.EstablishServerTLSFirst = tt.serverFirst
			}
			observer.startClient = func(d *hookdata.TLS) {
				d.DTLSConfig = &dtls.Config{Certificates: serverTLSConfig.Certificates, SupportedProtocols: []string{"custom"}} //nolint:staticcheck // Mutable TLS hook overrides.
			}
			observer.startServer = func(d *hookdata.TLS) {
				d.DTLSConfig = &dtls.Config{RootCAs: clientTLSConfig.RootCAs, ServerName: clientTLSConfig.ServerName, SupportedProtocols: []string{"custom"}} //nolint:staticcheck // Mutable TLS hook overrides.
			}
			observer.check = func(event string, d *hookdata.TLS) {
				if !d.IsDTLS || d.Config != nil {
					t.Errorf("%s: hook did not select DTLS", event)
				}
				if event == "tls_established_client" || event == "tls_established_server" {
					if !d.Conn.TLSEstablished() || d.Conn.TimestampTLSSetup == nil || d.Conn.Cipher == nil || d.Conn.TLSVersion != connection.DTLSv1_2 || string(d.Conn.ALPN) != "custom" {
						t.Errorf("%s: incomplete dispatch-published handshake metadata", event)
					}
					if d.IsServer() && len(d.Conn.CertificateList) == 0 {
						t.Errorf("%s: peer certificate not published", event)
					}
				}
			}
			if err := s.manager.Add(ctx, observer); err != nil {
				t.Fatal(err)
			}
			if err := s.manager.Do(ctx, func(context.Context) error {
				s.c.Data.Client.TransportProtocol = connection.UDP
				s.c.Data.Server.TransportProtocol = connection.UDP
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			s.c.ClientPackets, s.c.RecordPackets = proxy.RecordPackets(tuple), proxy.RecordPackets
			s.c.OpenPackets = func(_ context.Context, server *connection.Server) (layer.PacketTransport, *connection.Server, error) {
				return dtlsOriginTransport(t, origin.LocalAddr()), server, nil
			}
			if tt.preopened {
				s.c.ServerPackets = proxy.RecordPackets(dtlsOriginTransport(t, origin.LocalAddr()))
			}
			completed := make(chan struct{})
			child := innerLayer{kind: "test-dtls-relay", run: func(ctx context.Context, c *layer.Context) error {
				if c.ServerPackets == nil {
					var server *connection.Server
					if err := c.Do(ctx, func(context.Context) error { server = c.Data.Server; return nil }); err != nil {
						return err
					}
					packets, _, err := c.OpenPackets(ctx, server)
					if err != nil {
						return err
					}
					c.ServerPackets = c.RecordPackets(packets)
				}
				c.ClientPackets.StopRecording()
				c.ServerPackets.StopRecording()
				buf := make([]byte, 256)
				for range 100 {
					n, _, err := c.ClientPackets.ReadFrom(buf)
					if err != nil {
						return err
					}
					if _, err := c.ServerPackets.WriteTo(buf[:n], nil); err != nil {
						return err
					}
					n, _, err = c.ServerPackets.ReadFrom(buf)
					if err != nil {
						return err
					}
					if _, err := c.ClientPackets.WriteTo(buf[:n], nil); err != nil {
						return err
					}
				}
				select {
				case <-completed:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}}
			stack := &serverDTLS{child: &clientDTLS{child: child}}
			done := make(chan error, 1)
			go func() { done <- stack.Run(ctx, s.c) }()
			if err := await(t, peerDone); err != nil {
				t.Fatal(err)
			}
			_ = peer.SetDeadline(time.Now().Add(30 * time.Second))
			for i := range 100 {
				payload := []byte{byte(i), byte(i >> 8), 0, 255}
				if i == 0 {
					payload = []byte{}
				}
				if _, err := peer.Write(payload); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 256)
				n, err := peer.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(payload, buf[:n]); diff != "" {
					t.Fatalf("datagram %d: %s", i, diff)
				}
			}
			close(completed)
			if err := await(t, done); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
			if err := await(t, originDone); err != nil {
				t.Fatal(err)
			}
			want := []string{"tls_clienthello", "tls_start_client", "tls_established_client", "tls_start_server", "tls_established_server"}
			if tt.serverFirst {
				want = []string{"tls_clienthello", "tls_start_server", "tls_established_server", "tls_start_client", "tls_established_client"}
			}
			if diff := cmp.Diff(want, observer.events); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
