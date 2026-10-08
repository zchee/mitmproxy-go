// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h3"
)

// Each side owns its socket and Transport explicitly; neither is hidden behind
// ListenAddr, whose asynchronous connection cleanup can outlive the test.
func newHTTP3ConsumerPeer(t *testing.T, ctx context.Context, proxyClient bool) (*http3TestPeer, *quic.Conn) {
	t.Helper()
	key, ca, err := certs.CreateCA("HTTP3 consumer", "HTTP3 consumer root", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "localhost", []certs.GeneralName{certs.DNSName("localhost")}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.X509())
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw, ca.X509().Raw}, PrivateKey: key}}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, RootCAs: roots, ServerName: "localhost"}
	serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSocket.Close() })
	serverTransport := &quic.Transport{Conn: serverSocket}
	t.Cleanup(func() { _ = serverTransport.Close() })
	listener, err := serverTransport.Listen(serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSocket.Close() })
	clientTransport := &quic.Transport{Conn: clientSocket}
	t.Cleanup(func() { _ = clientTransport.Close() })
	client, err := clientTransport.Dial(ctx, serverSocket.LocalAddr(), clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0x100, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0x100, "") })
	peer, borrowed := client, server
	if proxyClient {
		peer, borrowed = server, client
	}
	peerCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			stream, err := peer.AcceptUniStream(peerCtx)
			if err != nil {
				return
			}
			workers.Go(func() { _, _ = io.Copy(io.Discard, stream) })
		}
	})
	t.Cleanup(func() {
		cancel()
		_ = peer.CloseWithError(0x100, "")
		workers.Wait()
	})
	for _, kind := range []uint64{0, 2, 3} {
		stream, err := peer.OpenUniStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		data := quicvarint.Append(nil, kind)
		if kind == 0 {
			data = append(data, 4, 4, 1, 0, 7, 0)
		}
		if _, err := stream.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	return &http3TestPeer{conn: peer}, borrowed
}

func TestHTTP3ConsumerBorrowedExchange(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ streamed bool }{"buffered": {}, "streamed": {streamed: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			seen := make(chan *flow.HTTPFlow, 1)
			addon := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				switch name {
				case "requestheaders":
					f.Request.Stream = test.streamed
				case "responseheaders":
					f.Response.Stream = test.streamed
				case "response":
					seen <- f
				}
			}}
			fixture, _ := newTestStream(t, addon)
			c := fixture.c
			if err := c.Do(ctx, func(context.Context) error {
				c.Data.Client.TransportProtocol = connection.UDP
				c.Data.Server.TransportProtocol = connection.UDP
				c.Data.Server.Address = &connection.Address{Host: "example.com", Port: 443}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			peer, client := newHTTP3ConsumerPeer(t, ctx, false)
			origin, server := newHTTP3ConsumerPeer(t, ctx, true)
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			joined := make(chan struct{})
			consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
			go func() { defer close(joined); done <- consumer.RunQUIC(runCtx, c, client, server) }()
			t.Cleanup(func() { cancel(); <-joined })
			request, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fields := []qpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/message"}, {Name: "x-foo", Value: "1"}, {Name: "x-bar", Value: "2"}, {Name: "x-foo", Value: "3"}}
			writeHTTP3TestHeaders(t, request, fields)
			writeHTTP3TestFrame(t, request, 0, []byte("request body"))
			if err := request.Close(); err != nil {
				t.Fatal(err)
			}
			upstream, err := origin.conn.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			gotFields, gotBody, _ := readHTTP3TestMessage(t, upstream)
			// The pinned formatter emits method, scheme, path, then authority;
			// regular duplicate fields retain their original relative order.
			wantFields := []qpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/message"}, {Name: ":authority", Value: "example.com"}, {Name: "x-foo", Value: "1"}, {Name: "x-bar", Value: "2"}, {Name: "x-foo", Value: "3"}}
			if diff := gocmp.Diff(wantFields, gotFields); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff("request body", string(gotBody)); diff != "" {
				t.Fatal(diff)
			}
			writeHTTP3TestHeaders(t, upstream, []qpack.HeaderField{{Name: ":status", Value: "200"}})
			writeHTTP3TestFrame(t, upstream, 0, []byte("response body"))
			if err := upstream.Close(); err != nil {
				t.Fatal(err)
			}
			_, gotBody, _ = readHTTP3TestMessage(t, request)
			if diff := gocmp.Diff("response body", string(gotBody)); diff != "" {
				t.Fatal(diff)
			}
			select {
			case f := <-seen:
				if err := c.Do(ctx, func(context.Context) error {
					if f.Request.HTTPVersion != "HTTP/3" || f.Response.HTTPVersion != "HTTP/3" || f.ClientConn.TLSVersion != connection.QUICv1 || f.ServerConn.TLSVersion != connection.QUICv1 {
						return errors.New("flow lost HTTP/3 or QUIC metadata")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			cancel()
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			<-joined
			if client.Context().Err() != nil || server.Context().Err() != nil {
				t.Fatal("consumer closed a borrowed QUIC connection")
			}
		})
	}
}

func TestHTTP3ConsumerSiblingIsolation(t *testing.T) {
	tests := map[string]struct{ resume bool }{"resume intercepted stream": {resume: true}, "reset intercepted stream": {}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			entered := make(chan *flow.HTTPFlow, 1)
			terminated := make(chan struct{})
			var pausedFlow *flow.HTTPFlow
			var terminalOnce sync.Once
			addon := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" && f.Request.Path == "/paused" {
					pausedFlow = f
					f.Intercept()
					entered <- f
				}
			}}
			fixture, master := newTestStream(t, addon)
			c := fixture.c
			c.Do = func(ctx context.Context, fn func(context.Context) error) error {
				return master.Do(ctx, func(ctx context.Context) error {
					err := fn(ctx)
					if pausedFlow != nil && !pausedFlow.Live {
						terminalOnce.Do(func() { close(terminated) })
					}
					return err
				})
			}
			if err := c.Do(ctx, func(context.Context) error {
				c.Data.Server.Address = &connection.Address{Host: "example.com", Port: 443}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			peer, client := newHTTP3ConsumerPeer(t, ctx, false)
			origin, server := newHTTP3ConsumerPeer(t, ctx, true)
			runCtx, cancel := context.WithCancel(ctx)
			joined := make(chan struct{})
			consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
			go func() { defer close(joined); _ = consumer.RunQUIC(runCtx, c, client, server) }()
			t.Cleanup(func() { cancel(); <-joined })
			paused, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, paused, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/paused"}, {Name: ":authority", Value: "example.com"}})
			if err := paused.Close(); err != nil {
				t.Fatal(err)
			}
			var intercepted *flow.HTTPFlow
			select {
			case intercepted = <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			free, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, free, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/free"}, {Name: ":authority", Value: "example.com"}})
			if err := free.Close(); err != nil {
				t.Fatal(err)
			}
			upstream, err := origin.conn.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fields, _, _ := readHTTP3TestMessage(t, upstream)
			if len(fields) < 3 || fields[2].Name != ":path" || fields[2].Value != "/free" {
				t.Fatalf("paused exchange reached origin before sibling: %+v", fields)
			}
			writeHTTP3TestHeaders(t, upstream, []qpack.HeaderField{{Name: ":status", Value: "204"}})
			if err := upstream.Close(); err != nil {
				t.Fatal(err)
			}
			readHTTP3TestMessage(t, free)
			if err := master.Do(ctx, func(context.Context) error {
				if !intercepted.Intercepted() {
					return errors.New("sibling completion released interception")
				}
				if test.resume {
					intercepted.Resume()
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if test.resume {
				upstream, err = origin.conn.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				readHTTP3TestMessage(t, upstream)
				writeHTTP3TestHeaders(t, upstream, []qpack.HeaderField{{Name: ":status", Value: "204"}})
				if err := upstream.Close(); err != nil {
					t.Fatal(err)
				}
				readHTTP3TestMessage(t, paused)
			} else {
				paused.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
				paused.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
				select {
				case <-terminated:
				case <-ctx.Done():
					t.Fatal("reset did not terminate the intercepted exchange:", ctx.Err())
				}
				if err := master.Do(ctx, func(context.Context) error {
					if pausedFlow.Live {
						return errors.New("reset left intercepted flow live")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHTTP3ConsumerConnectionFailure(t *testing.T) {
	tests := map[string]struct {
		disabled bool
		code     h3.ErrorCode
	}{
		"disabled option":           {disabled: true, code: h3.ErrCodeVersionFallback},
		"duplicate critical stream": {code: h3.ErrCodeStreamCreation},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			var specs []string
			if test.disabled {
				specs = []string{"http3=false"}
			}
			fixture, _ := newTestStream(t, &streamAddon{}, specs...)
			peer, client := newHTTP3ConsumerPeer(t, ctx, false)
			origin, server := newHTTP3ConsumerPeer(t, ctx, true)
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			joined := make(chan struct{})
			consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
			go func() { defer close(joined); done <- consumer.RunQUIC(runCtx, fixture.c, client, server) }()
			t.Cleanup(func() { cancel(); <-joined })
			if !test.disabled {
				duplicate, err := peer.conn.OpenUniStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := duplicate.Write([]byte{0, 4, 0}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				failure, ok := errors.AsType[*h3.ConnectionError](err)
				if !ok || failure.Code != test.code {
					t.Fatalf("consumer failure = %v; want %s", err, test.code)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			for _, conn := range []*quic.Conn{peer.conn, origin.conn} {
				select {
				case <-conn.Context().Done():
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				closed, ok := errors.AsType[*quic.ApplicationError](context.Cause(conn.Context()))
				if !ok || closed.ErrorCode != quic.ApplicationErrorCode(test.code) || closed.ErrorMessage != "" {
					t.Fatalf("protocol abort peer close = %v; want %s and no reason", context.Cause(conn.Context()), test.code)
				}
			}
		})
	}
}
