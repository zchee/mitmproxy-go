// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type http3RoutingTLS struct{}

func (*http3RoutingTLS) QUICStartServer(_ context.Context, data *hookdata.QUICTLS) error {
	data.Settings = &hookdata.QUICTLSSettings{ALPNProtocols: []string{"h3"}, VerifyMode: new(hookdata.VerifyNone)}
	return nil
}

type http3RoutingPackets struct {
	net.PacketConn
	ctx  context.Context
	peer net.Addr
}

func (p *http3RoutingPackets) Context() context.Context { return p.ctx }
func (p *http3RoutingPackets) RemoteAddr() net.Addr     { return p.peer }

func newHTTP3RoutingListener(t *testing.T) (*quic.Listener, *net.UDPAddr) {
	t.Helper()
	key, ca, err := certs.CreateCA("HTTP3 routing", "HTTP3 routing root", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "localhost", []certs.GeneralName{certs.DNSName("localhost")}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	transport := &quic.Transport{Conn: socket}
	t.Cleanup(func() { _ = transport.Close() })
	listener, err := transport.Listen(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw}, PrivateKey: key}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, socket.LocalAddr().(*net.UDPAddr)
}

func startHTTP3RoutingPeer(t *testing.T, ctx context.Context, conn *quic.Conn) {
	t.Helper()
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			stream, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			workers.Go(func() { _, _ = io.Copy(io.Discard, stream) })
		}
	})
	t.Cleanup(func() { _ = conn.CloseWithError(0x100, ""); workers.Wait() })
	for _, kind := range []uint64{0, 2, 3} {
		stream, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		data := quicvarint.Append(nil, kind)
		if kind == 0 {
			data = append(data, 4, 0)
		}
		if _, err := stream.Write(data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTP3ConsumerReroutedDestination(t *testing.T) {
	tests := map[string]struct{ requests int }{
		"request hook changes origin":              {requests: 1},
		"concurrent streams share rerouted origin": {requests: 2},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			listener, target := newHTTP3RoutingListener(t)
			addon := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "request" {
					f.Request.Host, f.Request.Port = target.IP.String(), target.Port
				}
			}}
			fixture, master := newTestStream(t, addon)
			c := fixture.c
			if err := master.Do(ctx, func(ctx context.Context) error {
				c.Data.Server.Address = &connection.Address{Host: "example.com", Port: 443}
				c.Data.Server.TransportProtocol = connection.UDP
				return master.Addons.Add(ctx, &http3RoutingTLS{})
			}); err != nil {
				t.Fatal(err)
			}
			selected := make(chan *connection.Server, 1)
			c.RecordPackets = proxy.RecordPackets
			c.OpenPackets = func(ctx context.Context, server *connection.Server) (layer.PacketTransport, *connection.Server, error) {
				selected <- server
				peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort(server.Address.Host, strconv.Itoa(server.Address.Port)))
				if err != nil {
					return nil, nil, err
				}
				socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					return nil, nil, err
				}
				t.Cleanup(func() { _ = socket.Close() })
				return &http3RoutingPackets{PacketConn: socket, ctx: ctx, peer: peer}, server, nil
			}
			peer, client := newHTTP3ConsumerPeer(t, ctx, false)
			oldOrigin, server := newHTTP3ConsumerPeer(t, ctx, true)
			runCtx, cancel := context.WithCancel(ctx)
			joined := make(chan struct{})
			consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
			go func() { defer close(joined); _ = consumer.RunQUIC(runCtx, c, client, server) }()
			t.Cleanup(func() { cancel(); <-joined })
			wrong := make(chan struct{})
			oldJoined := make(chan struct{})
			go func() {
				defer close(oldJoined)
				if _, err := oldOrigin.conn.AcceptStream(runCtx); err == nil {
					close(wrong)
				}
			}()
			t.Cleanup(func() { cancel(); <-oldJoined })
			requests := make([]*quic.Stream, 0, test.requests)
			for range test.requests {
				request, err := peer.conn.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				writeHTTP3TestHeaders(t, request, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/rerouted"}})
				if err := request.Close(); err != nil {
					t.Fatal(err)
				}
				requests = append(requests, request)
			}
			select {
			case actual := <-selected:
				if diff := gocmp.Diff(connection.Address{Host: target.IP.String(), Port: target.Port}, *actual.Address); diff != "" {
					t.Fatal(diff)
				}
			case <-wrong:
				t.Fatal("rerouted request was sent on the original QUIC connection")
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			origin, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = origin.CloseWithError(0x100, "") })
			startHTTP3RoutingPeer(t, runCtx, origin)
			for range test.requests {
				upstream, err := origin.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				fields, _, _ := readHTTP3TestMessage(t, upstream)
				if fields[2].Value != "/rerouted" {
					t.Fatal("rerouted request path lost:", fields)
				}
				writeHTTP3TestHeaders(t, upstream, []qpack.HeaderField{{Name: ":status", Value: "204"}})
				if err := upstream.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for _, request := range requests {
				readHTTP3TestMessage(t, request)
			}
			select {
			case <-selected:
				t.Fatal("concurrent streams opened separate QUIC origin connections")
			default:
			}
			if err := master.Do(ctx, func(context.Context) error {
				if len(addon.calls) == 0 || addon.calls[len(addon.calls)-1] != "response" {
					return errors.New("rerouted exchange did not complete response hooks")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
