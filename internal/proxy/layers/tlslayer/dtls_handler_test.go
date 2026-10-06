// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestDTLSReverseHandlerAcceptance(t *testing.T) {
	tests := map[string]struct {
		serverFirst bool
		noSNI       bool
	}{
		"success: eager origin handshake with SNI": {serverFirst: true},
		"success: lazy origin handshake with SNI":  {},
		"success: empty SNI on explicit listener":  {serverFirst: true, noSNI: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			key, ca, err := certs.CreateCA("DTLS test", "DTLS origin CA", 2048)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := certs.DummyCert(key, ca, "example.test", []certs.GeneralName{certs.DNSName("example.test"), certs.IPAddress(netip.MustParseAddr("127.0.0.1"))}, "", "")
			if err != nil {
				t.Fatal(err)
			}
			listener, err := dtls.Listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &dtls.Config{ //nolint:staticcheck // Exercise the pinned Config contract over a real origin listener.
				Certificates:       []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw, ca.X509().Raw}, PrivateKey: key}},
				CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				SupportedProtocols: []string{"custom"},
			})
			if err != nil {
				t.Fatal(err)
			}
			originStopped := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				_ = listener.Close()
				select {
				case <-originStopped:
				case <-time.After(30 * time.Second):
					buf := make([]byte, 1<<20)
					t.Fatalf("origin shutdown hung\n%s", buf[:runtime.Stack(buf, true)])
				}
			})
			originDone := make(chan error, 1)
			go func() {
				defer close(originStopped)
				conn, err := listener.Accept()
				if err != nil {
					originDone <- err
					return
				}
				defer func() { _ = conn.Close() }()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				buf := make([]byte, 256)
				for range 100 {
					n, err := conn.Read(buf)
					if err == nil {
						_, err = conn.Write(buf[:n])
					}
					if err != nil {
						originDone <- err
						return
					}
				}
				originDone <- nil
				// Leave the session open until the client has consumed the final reply.
				<-ctx.Done()
			}()
			observer := &dtlsAcceptanceObserver{serverFirst: tt.serverFirst}
			mode := "reverse:dtls://" + listener.Addr().String()
			if tt.noSNI {
				mode += "@127.0.0.1:0"
			}
			p := proxytest.Start(t,
				proxytest.WithOptions(map[string]any{
					"mode":           []string{mode},
					"ciphers_client": new("ECDHE-RSA-AES128-GCM-SHA256"),
					"ciphers_server": new("ECDHE-RSA-AES128-GCM-SHA256"),
				}),
				proxytest.WithTrustedCA(ca.X509()),
				proxytest.WithAddons(observer),
			)
			peer, err := net.ResolveUDPAddr("udp", p.Addr)
			if err != nil {
				t.Fatal(err)
			}
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = socket.Close() })
			serverName := "example.test"
			if tt.noSNI {
				serverName = ""
			}
			session, err := dtls.Client(socket, peer, &dtls.Config{ //nolint:staticcheck // Verify the actual interception constructor's wire protocol.
				RootCAs:            p.CAPool,
				ServerName:         serverName,
				CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				SupportedProtocols: []string{"custom"},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = session.Close() })
			stop := context.AfterFunc(ctx, func() { _ = session.Close() })
			defer stop()
			if err := session.HandshakeContext(ctx); err != nil {
				var events []string
				var failure string
				if inspectErr := p.Master.Do(context.WithoutCancel(ctx), func(context.Context) error {
					events, failure = slices.Clone(observer.events), observer.failure
					return nil
				}); inspectErr != nil {
					t.Errorf("inspect handshake failure: %v", inspectErr)
				}
				buf := make([]byte, 1<<20)
				t.Fatalf("client handshake: %v; hooks=%v; events=%v; failure=%q\n%s", err, p.Recorder.Hooks(), events, failure, buf[:runtime.Stack(buf, true)])
			}
			state, ok := session.ConnectionState()
			if !ok || len(state.PeerCertificates) == 0 {
				t.Fatal("client has no negotiated state or intercepted certificate")
			}
			intercepted, err := x509.ParseCertificate(state.PeerCertificates[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := intercepted.CheckSignatureFrom(p.CA); err != nil {
				t.Fatalf("intercepted leaf is not signed by the proxy CA: %v", err)
			}
			wantName := serverName
			if tt.noSNI {
				wantName = "127.0.0.1"
			}
			if err := intercepted.VerifyHostname(wantName); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(intercepted.Raw, leaf.X509().Raw) {
				t.Fatal("origin leaf passed through without interception")
			}
			if state.NegotiatedProtocol != "custom" || state.CipherSuiteID != dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
				t.Fatalf("negotiated ALPN/cipher = %q/%v", state.NegotiatedProtocol, state.CipherSuiteID)
			}
			for i := range 100 {
				payload := []byte{byte(i), byte(i >> 8), 0, 255}
				if i == 0 {
					payload = []byte{}
				}
				if _, err := session.Write(payload); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 256)
				n, err := session.Read(buf)
				if err != nil {
					stack := make([]byte, 1<<20)
					t.Fatalf("datagram %d: %v\n%s", i, err, stack[:runtime.Stack(stack, true)])
				}
				if diff := cmp.Diff(payload, buf[:n]); diff != "" {
					t.Fatalf("datagram %d (-sent +received): %s", i, diff)
				}
			}
			select {
			case err := <-originDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				buf := make([]byte, 1<<20)
				t.Fatalf("origin echo hung: %v\n%s", ctx.Err(), buf[:runtime.Stack(buf, true)])
			}
			if err := p.Master.Do(ctx, func(context.Context) error {
				if observer.sni != serverName {
					return fmt.Errorf("tls_clienthello SNI = %q, want %q", observer.sni, serverName)
				}
				want := []string{"tls_clienthello", "tls_start_client", "tls_established_client", "tls_start_server", "tls_established_server"}
				if tt.serverFirst {
					want = []string{"tls_clienthello", "tls_start_server", "tls_established_server", "tls_start_client", "tls_established_client"}
				}
				if diff := cmp.Diff(want, observer.events); diff != "" {
					return fmt.Errorf("hook order (-want +got): %s", diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Hook state is read only from hooks or the master's dispatch callback.
type dtlsAcceptanceObserver struct {
	serverFirst bool
	sni         string
	events      []string
	failure     string
}

func (o *dtlsAcceptanceObserver) ClientDisconnected(_ context.Context, client *connection.Client) error {
	if client.Error != nil {
		o.failure = *client.Error
	}
	return nil
}

func (*dtlsAcceptanceObserver) Name() string { return "dtls_acceptance" }

func (o *dtlsAcceptanceObserver) TLSClientHello(_ context.Context, d *hookdata.ClientHello) error {
	if !d.ClientHello.IsDTLS() {
		return errors.New("tls_clienthello did not identify DTLS")
	}
	o.sni = d.ClientHello.SNI()
	o.events = append(o.events, "tls_clienthello")
	d.EstablishServerTLSFirst = o.serverFirst
	return nil
}

func (o *dtlsAcceptanceObserver) TLSStartClient(_ context.Context, d *hookdata.TLS) error {
	return o.start("tls_start_client", d)
}

func (o *dtlsAcceptanceObserver) TLSStartServer(_ context.Context, d *hookdata.TLS) error {
	return o.start("tls_start_server", d)
}

func (o *dtlsAcceptanceObserver) start(event string, d *hookdata.TLS) error {
	if !d.IsDTLS || d.Config != nil || d.DTLSConfig == nil {
		return fmt.Errorf("%s did not select the DTLS addon configuration", event)
	}
	d.DTLSConfig.SupportedProtocols = []string{"custom"}
	o.events = append(o.events, event)
	return nil
}

func (o *dtlsAcceptanceObserver) TLSEstablishedClient(_ context.Context, d *hookdata.TLS) error {
	return o.established("tls_established_client", d)
}

func (o *dtlsAcceptanceObserver) TLSEstablishedServer(_ context.Context, d *hookdata.TLS) error {
	return o.established("tls_established_server", d)
}

func (o *dtlsAcceptanceObserver) established(event string, d *hookdata.TLS) error {
	if !d.IsDTLS || d.Config != nil || !d.Conn.TLSEstablished() || d.Conn.TimestampTLSSetup == nil || d.Conn.Cipher == nil || d.Conn.TLSVersion != connection.DTLSv1_2 || string(d.Conn.ALPN) != "custom" {
		return fmt.Errorf("%s did not publish negotiated DTLS state", event)
	}
	if d.IsServer() && len(d.Conn.CertificateList) == 0 {
		return errors.New("origin DTLS peer certificate was not published")
	}
	o.events = append(o.events, event)
	return nil
}

func (o *dtlsAcceptanceObserver) NextLayer(_ context.Context, d *hookdata.NextLayer) error {
	// Keep admission and DTLS selection real; replace only the decrypted child.
	if d.Context.Client.TLSEstablished() && d.Context.Client.TLSVersion == connection.DTLSv1_2 {
		d.Layer = hookdata.LayerStack{{Kind: "test-dtls-handler-relay"}}
	} else if len(d.Layer) != 0 && d.Layer[len(d.Layer)-1].Kind == hookdata.LayerUDP {
		want := hookdata.LayerStack{{Kind: hookdata.LayerServerDTLS}, {Kind: hookdata.LayerClientDTLS}, {Kind: hookdata.LayerUDP}}
		if diff := cmp.Diff(want, d.Layer); diff != "" {
			return fmt.Errorf("initial reverse DTLS selection (-want +got): %s", diff)
		}
		// Defer application construction until the DTLS handover asks for its child.
		d.Layer = d.Layer[:len(d.Layer)-1]
	}
	return nil
}

func init() {
	layer.Register("test-dtls-handler-relay", func(*layer.Context, hookdata.LayerSpec, layer.Layer) (layer.Layer, error) {
		return dtlsAcceptanceRelay{}, nil
	})
}

type dtlsAcceptanceRelay struct{}

func (dtlsAcceptanceRelay) Kind() hookdata.LayerKind { return "test-dtls-handler-relay" }

func (dtlsAcceptanceRelay) Run(ctx context.Context, c *layer.Context) error {
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
	buf := make([]byte, layer.MaxUDPPacketBytes)
	for {
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
}
