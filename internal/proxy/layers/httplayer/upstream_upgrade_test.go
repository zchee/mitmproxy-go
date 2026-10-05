// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/options"
)

const upstreamTLSProbeKind hookdata.LayerKind = "test-upstream-tls"

type (
	upstreamTLSProbeKey struct{}
	upstreamTLSProbe    struct{}
)

func init() {
	layer.Register(upstreamTLSProbeKind, func(*layer.Context, hookdata.LayerSpec, layer.Layer) (layer.Layer, error) {
		return upstreamTLSProbe{}, nil
	})
}

func (upstreamTLSProbe) Kind() hookdata.LayerKind { return upstreamTLSProbeKind }

func (upstreamTLSProbe) Run(ctx context.Context, c *layer.Context) error {
	return ctx.Value(upstreamTLSProbeKey{}).(func(context.Context, *layer.Context) error)(ctx, c)
}

type upstreamTLSObserver struct {
	server      *tls.Config
	client      *tls.Config
	serverFirst bool
	established []string
}

func (*upstreamTLSObserver) Name() string { return "upstream-tls-observer" }

func (o *upstreamTLSObserver) TLSClienthello(_ context.Context, data *hookdata.ClientHello) error {
	data.EstablishServerTLSFirst = o.serverFirst
	return nil
}

func (o *upstreamTLSObserver) TLSStartClient(_ context.Context, data *hookdata.TLS) error {
	data.Config = o.server.Clone()
	return nil
}

func (o *upstreamTLSObserver) TLSStartServer(_ context.Context, data *hookdata.TLS) error {
	data.Config = o.client.Clone()
	data.Config.ServerName = data.Context.Server.Address.Host
	data.Context.Server.SNI = new(data.Config.ServerName)
	return nil
}

func (o *upstreamTLSObserver) TLSEstablishedServer(_ context.Context, data *hookdata.TLS) error {
	o.established = append(o.established, data.Context.Server.Address.Host)
	return nil
}

func upstreamTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "origin.test"},
		DNSNames:  []string{"origin.test", "proxy.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}},
		&tls.Config{RootCAs: roots, ServerName: "origin.test"}
}

// Open a real HTTPS-proxy tunnel before selecting server TLS. This exercises
// Upgrade, not the ordinary Open-with-Setup path used by lazy HTTP routing.
func TestUpstreamPoolNestedTLSUpgrade(t *testing.T) {
	tests := map[string]struct {
		deferred    bool
		serverFirst bool
	}{
		"success: eager origin TLS": {},
		"success: client first":     {deferred: true},
		"success: server first":     {deferred: true, serverFirst: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pool, peers, lifecycle := newUpstreamPoolSession(t)
			pool.connect = true
			serverConfig, clientConfig := upstreamTLSConfigs(t)
			observer := &upstreamTLSObserver{server: serverConfig, client: clientConfig, serverFirst: tt.serverFirst}
			if err := pool.c.Hooks.(*proxy.HookRunner).Manager.Add(t.Context(), observer); err != nil {
				t.Fatal(err)
			}
			if err := pool.c.Data.Options.Add(t.Context(), "http_connect_send_host_header", options.TypeBool, true, "Send a Host header in CONNECT requests."); err != nil {
				t.Fatal(err)
			}
			srv := upstreamOrigin("origin.test")
			srv.Address.Port = 443
			srv.Via.Scheme = "https"
			if err := pool.c.Do(t.Context(), func(context.Context) error {
				pool.c.Data.Server = srv
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			type opened struct {
				conn layer.Conn
				err  error
			}
			opening := make(chan opened, 1)
			go func() {
				conn, _, err := pool.Open(t.Context(), srv, layer.OpenOptions{Reuse: true})
				opening <- opened{conn, err}
			}()
			peer := await(t, peers)
			served := make(chan error, 1)
			go func() {
				parent := tls.Server(peer, serverConfig)
				request, err := http.ReadRequest(bufio.NewReader(parent))
				if err != nil {
					served <- err
					return
				}
				if request.Method != "CONNECT" || request.RequestURI != "origin.test:443" || parent.ConnectionState().ServerName != "proxy.test" {
					served <- fmt.Errorf("wrong parent routing: %s %s SNI=%q", request.Method, request.RequestURI, parent.ConnectionState().ServerName)
					return
				}
				if _, err := io.WriteString(parent, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					served <- err
					return
				}
				origin := tls.Server(parent, serverConfig)
				ping := make([]byte, 4)
				if _, err := io.ReadFull(origin, ping); err != nil {
					served <- err
					return
				}
				if string(ping) != "ping" || origin.ConnectionState().ServerName != "origin.test" {
					served <- fmt.Errorf("wrong origin exchange: %q SNI=%q", ping, origin.ConnectionState().ServerName)
					return
				}
				if _, err := io.WriteString(origin, "pong"); err != nil {
					served <- err
					return
				}
				_, err = io.Copy(io.Discard, origin)
				served <- err
			}()
			peerJoined := false
			t.Cleanup(func() {
				_ = peer.Close()
				if !peerJoined {
					_ = await(t, served)
				}
			})
			openedResult := await(t, opening)
			if openedResult.err != nil {
				t.Fatal(openedResult.err)
			}
			original := openedResult.conn
			physical := await(t, lifecycle.connected)
			c := *pool.c
			c.Pool, c.Server = pool, proxy.Record(original)
			clientRaw, clientPeer := layertest.Pipe(t)
			c.Client = proxy.Record(clientRaw)
			probe := func(ctx context.Context, c *layer.Context) error {
				conn, actual, err := c.Pool.Open(ctx, srv, layer.OpenOptions{Reuse: true})
				if err != nil {
					return err
				}
				if conn != original || actual != srv {
					return errors.New("upgrade replaced the stable logical connection")
				}
				if _, err := conn.Write([]byte("ping")); err != nil {
					return err
				}
				pong := make([]byte, 4)
				if _, err := io.ReadFull(conn, pong); err != nil {
					return err
				}
				if string(pong) != "pong" {
					return fmt.Errorf("origin replied %q", pong)
				}
				return conn.Close()
			}
			ctx := context.WithValue(t.Context(), upstreamTLSProbeKey{}, probe)
			stack := hookdata.LayerStack{{Kind: hookdata.LayerServerTLS}}
			if tt.deferred {
				stack = append(stack, hookdata.LayerSpec{Kind: hookdata.LayerClientTLS})
			}
			stack = append(stack, hookdata.LayerSpec{Kind: upstreamTLSProbeKind})
			built, err := layer.Build(ctx, &c, stack)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- built.Run(ctx, &c) }()
			if tt.deferred {
				if err := tls.Client(clientPeer, clientConfig).HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			peerErr := await(t, served)
			peerJoined = true
			if peerErr != nil {
				t.Fatalf("origin TLS shutdown: %v", peerErr)
			}
			closed := await(t, lifecycle.disconnected)
			if closed.ID != physical.ID || len(lifecycle.connected) != 0 || len(peers) != 0 {
				t.Fatal("logical TLS upgrade changed physical lifecycle ownership")
			}
			if err := c.Do(ctx, func(context.Context) error {
				if len(observer.established) != 2 || observer.established[0] != "proxy.test" || observer.established[1] != "origin.test" {
					return fmt.Errorf("TLS established order = %v", observer.established)
				}
				if srv.TimestampTLSSetup == nil || srv.TLSVersion == "" || srv.State != connection.Closed {
					return fmt.Errorf("logical TLS metadata = %+v", srv)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
