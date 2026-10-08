// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	quicgo "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/modeserver"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/options"
)

// Cold full-tree race failures hit the default idle budget at 30.46s and
// 30.33s. Keep the test peer active while dispatch catches up.
const wireClientKeepAlivePeriod = time.Second

const wireWaitTimeout = 30 * time.Second

type wireObserver struct {
	events              []string
	hello               func(*hookdata.ClientHello)
	sni                 string
	ended               chan *flow.TCPFlow
	started             chan *flow.TCPFlow
	udpStarted          chan *flow.UDPFlow
	expectOriginFailure bool
	failed              chan struct{}
	disconnected        chan struct{}
	connectionID        string
	message             func(context.Context, *flow.TCPFlow) error
	consumer            ConnectionConsumer
	clientIdleTimeout   time.Duration
	established         chan struct{}
	serverEstablished   chan struct{}
	passthrough         bool
	preserveSettings    bool
	clientSettings      *hookdata.QUICTLSSettings
	clientTLS           *hookdata.QUICTLS
}

func (o *wireObserver) TLSClientHello(_ context.Context, d *hookdata.ClientHello) error {
	o.events = append(o.events, "hello")
	o.sni = d.ClientHello.SNI()
	if o.hello != nil {
		o.hello(d)
	}
	return nil
}

func (o *wireObserver) QUICStartClient(_ context.Context, data *hookdata.QUICTLS) error {
	o.events = append(o.events, "start-client")
	if o.clientSettings != nil {
		data.Settings = o.clientSettings
		o.clientTLS = data
	}
	return nil
}

func (o *wireObserver) QUICStartServer(context.Context, *hookdata.QUICTLS) error {
	o.events = append(o.events, "start-server")
	return nil
}

func (o *wireObserver) TLSEstablishedClient(context.Context, *hookdata.TLS) error {
	o.events = append(o.events, "established-client")
	if o.established != nil {
		o.established <- struct{}{}
	}
	return nil
}

func (o *wireObserver) TLSEstablishedServer(context.Context, *hookdata.TLS) error {
	o.events = append(o.events, "established-server")
	if o.serverEstablished != nil {
		o.serverEstablished <- struct{}{}
	}
	return nil
}

func (o *wireObserver) TLSFailedServer(context.Context, *hookdata.TLS) error {
	o.events = append(o.events, "failed-server")
	if o.failed != nil {
		o.failed <- struct{}{}
	}
	return nil
}

func (o *wireObserver) TCPStart(_ context.Context, f *flow.TCPFlow) error {
	if o.started != nil {
		o.started <- f
	}
	return nil
}

func (o *wireObserver) TCPMessage(ctx context.Context, f *flow.TCPFlow) error {
	if o.message != nil {
		return o.message(ctx, f)
	}
	m := f.Messages[len(f.Messages)-1]
	m.Content = bytes.ToUpper(m.Content)
	return nil
}

func (o *wireObserver) TCPEnd(_ context.Context, f *flow.TCPFlow) error {
	o.ended <- f.Copy().(*flow.TCPFlow)
	return nil
}

func (o *wireObserver) TCPError(_ context.Context, f *flow.TCPFlow) error {
	o.ended <- f.Copy().(*flow.TCPFlow)
	return nil
}

func wireAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(wireWaitTimeout):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("QUIC fixture did not complete:\n%s", buf[:n])
		var zero T
		return zero
	}
}

func wireAwaitServerEstablished(t *testing.T, o *wireObserver) {
	t.Helper()
	wireAwait(t, o.serverEstablished)
}

func originCertificate(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "QUIC fixture root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"two-datagram.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"raw-test"}, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key}}}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

type wireSession struct {
	ctx             context.Context
	cancel          context.CancelFunc
	manager         *addon.Manager
	handler         *proxy.Handler
	observer        *wireObserver
	origin, client  *quicgo.Conn
	originListener  *quicgo.Listener
	originTransport *quicgo.Transport
	originSocket    net.PacketConn
	mode            *modeserver.Instance
	workers         sync.WaitGroup
	originReady     chan *quicgo.Conn
}

func newWireSession(t *testing.T, optsMap map[string]any, observe *wireObserver) *wireSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	s := &wireSession{ctx: ctx, cancel: cancel, observer: observe, originReady: make(chan *quicgo.Conn, 1)}
	observe.disconnected = make(chan struct{}, 1)
	observe.established = make(chan struct{}, 1)
	observe.serverEstablished = make(chan struct{}, 1)
	t.Cleanup(func() {
		cancel()
		if s.client != nil {
			_ = s.client.CloseWithError(0, "")
		}
		if s.origin != nil {
			_ = s.origin.CloseWithError(0, "")
		}
		if s.mode != nil {
			_ = s.mode.Stop()
		}
		if s.originListener != nil {
			_ = s.originListener.Close()
		}
		if s.originTransport != nil {
			_ = s.originTransport.Close()
		}
		if s.originSocket != nil {
			_ = s.originSocket.Close()
		}
		s.workers.Wait()
		if s.client != nil {
			wireAwait(t, observe.disconnected)
		}
		if s.manager != nil {
			s.manager.Close()
		}
	})
	originTLS, rootPEM := originCertificate(t)
	if observe.preserveSettings {
		leaf, err := x509.ParseCertificate(originTLS.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		root, err := x509.ParseCertificate(originTLS.Certificates[0].Certificate[1])
		if err != nil {
			t.Fatal(err)
		}
		observe.clientSettings = &hookdata.QUICTLSSettings{ALPNProtocols: []string{"raw-test"}, Certificate: leaf, CertificateChain: []*x509.Certificate{root}, CertificatePrivateKey: originTLS.Certificates[0].PrivateKey}
	}
	var err error
	s.originSocket, err = net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// ListenAddr hides a transport that outlives Listener.Close while closed
	// connection IDs remain cached. Own it explicitly so leak checks follow joins.
	s.originTransport = &quicgo.Transport{Conn: s.originSocket}
	s.originListener, err = s.originTransport.Listen(originTLS, transportConfig())
	if err != nil {
		t.Fatal(err)
	}
	s.workers.Go(func() {
		conn, err := s.originListener.Accept(ctx)
		if err == nil {
			s.originReady <- conn
		} else {
			s.originReady <- nil
		}
	})
	opts := options.New()
	if err := opts.Add(ctx, "connection_strategy", options.TypeStr, "eager", "Determine when server connections should be established."); err != nil {
		t.Fatal(err)
	}
	if observe.consumer != nil {
		consumerFixtures.Store(opts, observe.consumer)
		t.Cleanup(func() { consumerFixtures.Delete(opts) })
	}
	if err := opts.Add(ctx, "keep_host_header", options.TypeBool, false, "Reverse Proxy: Keep the original host header instead of rewriting it to the reverse proxy target."); err != nil {
		t.Fatal(err)
	}
	confdir := t.TempDir()
	if err := opts.Update(ctx, map[string]any{"confdir": confdir}); err != nil {
		t.Fatal(err)
	}
	s.manager = addon.NewManager(opts, command.NewManager(), addon.Config{})
	selector := nextlayer.New(opts)
	defaults := tlsconfig.New(opts)
	for _, a := range []any{observe, selector, defaults} {
		if err := s.manager.Add(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.manager.Do(ctx, defaults.Running); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(confdir, "origin.pem")
	if err := os.WriteFile(rootPath, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"keep_host_header": true, "ssl_verify_upstream_trusted_ca": new(rootPath)}
	maps.Copy(settings, optsMap)
	if err := s.manager.Do(ctx, func(ctx context.Context) error { return opts.Update(ctx, settings) }); err != nil {
		t.Fatal(err)
	}
	s.handler, err = proxy.NewHandler(proxy.Config{Manager: s.manager, Options: opts, Connections: &proxy.Connections{}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := modespec.Parse("reverse:quic://" + s.originListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s.mode, err = modeserver.New(spec, modeserver.Config{Handler: s.handler, ListenHost: "127.0.0.1", ListenPort: new(0), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.mode.Start(ctx); err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	clientRoots.AppendCertsFromPEM(caPEM)
	if _, ignored := optsMap["ignore_hosts"]; ignored || observe.hello != nil || observe.preserveSettings {
		clientRoots.AppendCertsFromPEM(rootPEM)
	}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := &quicgo.Transport{Conn: socket}
	t.Cleanup(func() { _ = transport.Close(); _ = socket.Close() })
	addr := s.mode.ListenAddrs()[0]
	peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addr.Host, fmt.Sprint(addr.Port)))
	if err != nil {
		t.Fatal(err)
	}
	clientQUIC := transportConfig()
	clientQUIC.KeepAlivePeriod = wireClientKeepAlivePeriod
	if observe.clientIdleTimeout > 0 {
		clientQUIC.MaxIdleTimeout = observe.clientIdleTimeout
		clientQUIC.KeepAlivePeriod = observe.clientIdleTimeout / 3
	}
	s.client, err = transport.Dial(ctx, peer, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"raw-test"}, ServerName: "two-datagram.example", RootCAs: clientRoots, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}, clientQUIC)
	if err != nil && !observe.expectOriginFailure {
		t.Fatal(err)
	}
	if observe.expectOriginFailure {
		wireAwait(t, observe.failed)
		if s.client != nil {
			wireAwait(t, observe.established)
		}
		return s
	}
	if !observe.passthrough {
		wireAwait(t, observe.established)
	}
	s.origin = wireAwait(t, s.originReady)
	if s.origin == nil {
		t.Fatal("origin handshake failed")
	}
	return s
}

func TestQUICWireStreams(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	// py:test/mitmproxy/proxy/layers/quic/test__raw_layers.py stream/data/reset rows.
	tests := map[string]struct{ fromClient, uni bool }{
		"client bidirectional": {fromClient: true}, "server bidirectional": {},
		"client unidirectional": {fromClient: true, uni: true}, "server unidirectional": {uni: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 100)}
			s := newWireSession(t, nil, o)
			sender, receiver := s.client, s.origin
			if !tt.fromClient {
				sender, receiver = receiver, sender
			}
			if tt.uni {
				stream, err := sender.OpenUniStreamSync(s.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Write([]byte("hello")); err != nil {
					t.Fatal(err)
				}
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
				peer, err := receiver.AcceptUniStream(s.ctx)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(peer)
				if err != nil || string(data) != "HELLO" {
					t.Fatalf("uni payload=%q,%v", data, err)
				}
			} else {
				stream, err := sender.OpenStreamSync(s.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Write([]byte("hello")); err != nil {
					t.Fatal(err)
				}
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
				peer, err := receiver.AcceptStream(s.ctx)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(peer)
				if err != nil || string(data) != "HELLO" {
					t.Fatalf("forward payload=%q,%v", data, err)
				}
				if _, err := peer.Write([]byte("reply")); err != nil {
					t.Fatal(err)
				}
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
				data, err = io.ReadAll(stream)
				if err != nil || string(data) != "REPLY" {
					t.Fatalf("reverse after FIN=%q,%v", data, err)
				}
			}
			f := wireAwait(t, o.ended)
			if f.Error != nil {
				t.Fatalf("stream flow error=%v", f.Error)
			}
			wantInitiator := "server"
			if tt.fromClient {
				wantInitiator = "client"
			}
			if value, _ := f.Metadata.Get("quic_initiator"); value != wantInitiator {
				t.Errorf("initiator=%v", value)
			}
			if value, _ := f.Metadata.Get("quic_is_unidirectional"); value != tt.uni {
				t.Errorf("uni=%v", value)
			}
			if err := s.manager.Do(s.ctx, func(context.Context) error {
				if o.sni != "two-datagram.example" {
					t.Errorf("sniffed SNI=%q", o.sni)
				}
				want := []string{"hello", "start-server", "established-server", "start-client", "established-client"}
				if diff := gocmp.Diff(want, o.events); diff != "" {
					t.Error(diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQUICWirePassthrough(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	tests := map[string]struct{ ignoreHook bool }{"ignore_hosts": {}, "ignore_connection": {ignoreHook: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 1), passthrough: true}
			settings := map[string]any{"ignore_hosts": []string{"two-datagram.example"}}
			if tt.ignoreHook {
				settings = nil
				o.hello = func(d *hookdata.ClientHello) { d.IgnoreConnection = true }
			}
			s := newWireSession(t, settings, o)
			stream, err := s.client.OpenStreamSync(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = stream.Write([]byte("encrypted passthrough"))
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.Close()
			peer, err := s.origin.AcceptStream(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(peer)
			if err != nil || string(got) != "encrypted passthrough" {
				t.Fatalf("passthrough=%q,%v", got, err)
			}
			if err := s.manager.Do(s.ctx, func(context.Context) error {
				want := []string(nil)
				if tt.ignoreHook {
					want = []string{"hello"}
				}
				if diff := gocmp.Diff(want, o.events); diff != "" {
					t.Error(diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQUICWireReset(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	tests := map[string]struct{ code quicgo.StreamErrorCode }{"reset code": {code: 42}, "maximum reset code": {code: 1<<62 - 1}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 1)}
			s := newWireSession(t, nil, o)
			stream, err := s.client.OpenStreamSync(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = stream.Write([]byte("hello"))
			if err != nil {
				t.Fatal(err)
			}
			peer, err := s.origin.AcceptStream(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 5)
			if _, err := io.ReadFull(peer, buf); err != nil {
				t.Fatal(err)
			}
			stream.CancelWrite(tt.code)
			_, err = peer.Read(buf)
			reset, ok := errors.AsType[*quicgo.StreamError](err)
			if !ok || reset.ErrorCode != tt.code {
				t.Fatalf("reset=%v", err)
			}
			_ = peer.Close()
			if _, err := io.ReadAll(stream); err != nil {
				t.Fatal(err)
			}
			wireAwait(t, o.ended)
		})
	}
}
