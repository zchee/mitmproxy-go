// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h3"
)

type http3ClosePublicationTrace struct {
	closed  chan qlog.ConnectionClosed
	release chan struct{}
}

func (g *http3ClosePublicationTrace) AddProducer() qlogwriter.Recorder { return g }
func (*http3ClosePublicationTrace) SupportsSchemas(string) bool        { return true }
func (*http3ClosePublicationTrace) Close() error                       { return nil }

func (g *http3ClosePublicationTrace) RecordEvent(event qlogwriter.Event) {
	closed, ok := event.(qlog.ConnectionClosed)
	if !ok || closed.Initiator != qlog.InitiatorRemote || closed.ApplicationError == nil {
		return
	}
	// Readers already hold the remote error; Conn.Context is published only
	// after this callback. No transport-library patch creates the window.
	g.closed <- closed
	<-g.release
}

func newHTTP3AbortPublicationPeer(t *testing.T, ctx context.Context, trace qlogwriter.Trace) (*quic.Conn, *quic.Conn) {
	t.Helper()
	key, ca, err := certs.CreateCA("HTTP3 abort", "HTTP3 abort root", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "localhost", []certs.GeneralName{certs.DNSName("localhost")}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSocket.Close() })
	serverTransport := &quic.Transport{Conn: serverSocket}
	t.Cleanup(func() { _ = serverTransport.Close() })
	listener, err := serverTransport.Listen(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw}, PrivateKey: key}}}, &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }})
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
	peer, err := clientTransport.Dial(ctx, serverSocket.LocalAddr(), &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, InsecureSkipVerify: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.CloseWithError(0x100, "") })
	borrowed, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = borrowed.CloseWithError(0x100, "") })
	startHTTP3RoutingPeer(t, ctx, peer)
	return peer, borrowed
}

func TestHTTP3ConsumerAbortBeforeContextPublication(t *testing.T) {
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:test_http3_client_aborts.
	ctx := http3TestContext(t)
	gate := &http3ClosePublicationTrace{closed: make(chan qlog.ConnectionClosed, 1), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	var observed *flow.HTTPFlow
	var errorCount int
	started, errored, terminal := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{})
	terminalOnce := sync.OnceFunc(func() { close(terminal) })
	fixture, master := newTestStream(t, &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		switch name {
		case "requestheaders":
			observed = f
		case "responseheaders":
			f.Response.Stream = true
			started <- struct{}{}
		case "error":
			errorCount++
			errored <- struct{}{}
		}
	}})
	if err := master.Do(ctx, func(context.Context) error {
		fixture.c.Data.Server.Address = &connection.Address{Host: "example.com", Port: 443}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fixture.c.Do = func(ctx context.Context, fn func(context.Context) error) error {
		return master.Do(ctx, func(ctx context.Context) error {
			err := fn(ctx)
			if observed != nil && !observed.Live {
				terminalOnce()
			}
			return err
		})
	}
	peer, client := newHTTP3AbortPublicationPeer(t, ctx, gate)
	origin, server := newHTTP3ConsumerPeer(t, ctx, true)
	runCtx, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	result := make(chan error, 1)
	consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
	go func() { defer close(joined); result <- consumer.RunQUIC(runCtx, fixture.c, client, server) }()
	defer func() { unblock(); cancel(); <-joined }()
	request, err := peer.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writeHTTP3TestHeaders(t, request, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/aborted"}})
	if err := request.Close(); err != nil {
		t.Fatal(err)
	}
	upstream, err := origin.conn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readHTTP3TestMessage(t, upstream)
	writeHTTP3TestHeaders(t, upstream, []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: "6"}})
	writeHTTP3TestFrame(t, upstream, 0, []byte("123"))
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// A wire-observed response proves HEADERS reached the client before abort.
	readHTTP3TestHeaders(t, request)
	if err := peer.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeRequestCancelled), "remote response abort"); err != nil {
		t.Fatal(err)
	}
	select {
	case closed := <-gate.closed:
		if uint64(*closed.ApplicationError) != uint64(h3.ErrCodeRequestCancelled) || closed.Reason != "remote response abort" {
			t.Fatalf("traced close: %+v", closed)
		}
	case <-ctx.Done():
		t.Fatal("close publication gate:", ctx.Err())
	}
	if client.Context().Err() != nil {
		t.Fatal("context was published before gate release")
	}
	select {
	case <-errored:
	case <-ctx.Done():
		t.Fatal("abort did not produce error hook:", ctx.Err())
	}
	select {
	case <-terminal:
	case <-ctx.Done():
		t.Fatal("abort left flow live:", ctx.Err())
	}
	unblock()
	select {
	case err := <-result:
		failure, ok := errors.AsType[*h3.ConnectionError](err)
		if !ok || failure.Code != h3.ErrCodeRequestCancelled || !strings.Contains(failure.Message, "remote response abort") {
			t.Fatalf("consumer close cause = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("consumer did not join:", ctx.Err())
	}
	if err := master.Do(ctx, func(context.Context) error {
		if errorCount != 1 || observed.Error == nil {
			return fmt.Errorf("error hooks=%d flow error=%v", errorCount, observed.Error)
		}
		if !strings.Contains(observed.Error.Msg, "remote response abort") {
			return fmt.Errorf("flow close cause = %q", observed.Error.Msg)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
