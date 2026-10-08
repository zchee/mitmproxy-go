// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestEndpointExchange(t *testing.T) {
	ignored := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, ignored) })
	tests := map[string]struct {
		body string
	}{
		"headers only": {},
		"body bytes":   {body: "unmodified body"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, server, ctx := newEndpointPair(t)
			id, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if id.Stream != 0 || id.Endpoint != "origin" {
				t.Fatalf("first request identity = %+v", id)
			}
			fields := []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "localhost"}, {Name: ":path", Value: "/"}, {Name: "x-duplicate", Value: "first"}, {Name: "x-duplicate", Value: "second"}}
			if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: fields, EndStream: test.body == ""}); err != nil {
				t.Fatal(err)
			}
			head, err := server.Receive(ctx)
			if err != nil || head.Kind != Headers || head.Identity.Stream != id.Stream || head.Identity.Endpoint != "client" {
				t.Fatalf("request head = %+v, %v", head, err)
			}
			if diff := gocmp.Diff(fields, head.Headers); diff != "" {
				t.Fatalf("ordered request fields (-want +got):\n%s", diff)
			}
			if test.body != "" {
				if err := client.Send(ctx, Event{Kind: Data, Identity: id, Data: []byte(test.body), EndStream: true}); err != nil {
					t.Fatal(err)
				}
			}
			var body []byte
			for !head.EndStream {
				head, err = server.ReceiveStream(ctx, head.Identity)
				if err != nil || head.Kind != Data || head.Receipt == nil {
					t.Fatalf("request DATA = %+v, %v", head, err)
				}
				if head.Receipt.OriginalBytes() != len(head.Data) || cap(head.Data) > ChunkSize {
					t.Fatalf("DATA accounting: original=%d bytes=%d capacity=%d", head.Receipt.OriginalBytes(), len(head.Data), cap(head.Data))
				}
				body = append(body, head.Data...)
				if !head.Receipt.Complete() || head.Receipt.Complete() {
					t.Fatal("receipt settlement was not exactly once")
				}
			}
			if diff := gocmp.Diff(test.body, string(body)); diff != "" {
				t.Fatalf("request body (-want +got):\n%s", diff)
			}
			info := []HeaderField{{Name: ":status", Value: "103"}}
			if err := server.Send(ctx, Event{Kind: Informational, Identity: head.Identity, Headers: info}); err != nil {
				t.Fatal(err)
			}
			response := []HeaderField{{Name: ":status", Value: "200"}, {Name: "x-duplicate", Value: "one"}, {Name: "x-duplicate", Value: "two"}}
			if err := server.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: response, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			for _, want := range []Event{{Kind: Informational, Headers: info}, {Kind: Headers, Headers: response}} {
				got, err := client.ReceiveStream(ctx, id)
				if err != nil || got.Kind != want.Kind {
					t.Fatalf("response event = %+v, %v; want kind %v", got, err, want.Kind)
				}
				if diff := gocmp.Diff(want.Headers, got.Headers); diff != "" {
					t.Fatalf("response fields (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func newEndpointPair(t *testing.T, expectedFailure ...ErrorCode) (*Endpoint, *Endpoint, context.Context) {
	t.Helper()
	// Testing cancels its context before cleanup callbacks. Let this fixture
	// close both peers before cancelling their stream owners instead.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
	t.Cleanup(cancel)
	return newEndpointPairContexts(t, ctx, ctx, cancel, expectedFailure)
}

func newEndpointPairContexts(t *testing.T, ctx, serverCtx context.Context, cancel context.CancelFunc, expectedFailure []ErrorCode) (*Endpoint, *Endpoint, context.Context) {
	t.Helper()
	key, ca, err := certs.CreateCA("Endpoint contract", "Endpoint contract root", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "localhost", []certs.GeneralName{certs.DNSName("localhost")}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.X509())
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw}, PrivateKey: key}}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, RootCAs: roots, ServerName: "localhost"}
	var transports []*quicTransport
	var sockets []net.PacketConn
	var conns []*quicConnection
	var listener *quicListener
	var finished []<-chan error
	t.Cleanup(func() {
		// Quiesce both peer connections before cancelling their stream owners;
		// otherwise a peer can observe critical-stream resets during teardown.
		for _, conn := range conns {
			if err := conn.closeWithError(0x100); err != nil {
				t.Error(err)
			}
		}
		cancel()
		for _, done := range finished {
			select {
			case err := <-done:
				failure, expected := errors.AsType[*ConnectionError](err)
				expected = expected && len(expectedFailure) == 1 && failure.Code == expectedFailure[0]
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && !expected {
					t.Errorf("Run cleanup: %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Error("Run did not join its workers")
			}
		}
		if listener != nil {
			if err := listener.close(); err != nil {
				t.Error(err)
			}
		}
		for _, transport := range transports {
			if err := transport.close(); err != nil {
				t.Error(err)
			}
		}
		for _, socket := range sockets {
			if err := socket.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	for range 2 {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, socket)
		transports = append(transports, newQUICTransport(socket))
	}
	listener, err = transports[0].listen(serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := transports[1].dial(ctx, sockets[0].LocalAddr(), clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	conns = append(conns, clientConn)
	serverConn, err := listener.accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conns = append(conns, serverConn)
	client, err := New(clientConn.conn, Config{Descriptor: layer.EndpointDescriptor{Identity: "origin", Protocol: "h3"}, Client: true})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(serverConn.conn, Config{Descriptor: layer.EndpointDescriptor{Identity: "client", Protocol: "h3"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, endpoint := range []*Endpoint{client, server} {
		runCtx := ctx
		if i == 1 {
			runCtx = serverCtx
		}
		done := make(chan error, 1)
		finished = append(finished, done)
		go func() { done <- endpoint.Run(runCtx) }()
	}
	return client, server, ctx
}
