// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package h3test provides frame-level HTTP/3 peers on real loopback QUIC sockets.
package h3test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/zchee/mitmproxy-go/certs"
)

// Peer owns the wire side of a test connection. Control carries peer control frames.
type Peer struct {
	Conn    *quic.Conn
	Control chan Frame
}

// Listener opens an explicitly owned QUIC listener and returns its trusted client settings.
// The test cleanup closes the listener, transport and UDP socket.
func Listener(t *testing.T) (*quic.Listener, *tls.Config) {
	t.Helper()
	key, ca, err := certs.CreateCA("HTTP3 acceptance", "HTTP3 acceptance root", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "localhost", []certs.GeneralName{certs.DNSName("localhost")}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.X509())
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	transport := &quic.Transport{Conn: socket}
	t.Cleanup(func() { _ = transport.Close() })
	listener, err := transport.Listen(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.X509().Raw, ca.X509().Raw}, PrivateKey: key}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, RootCAs: roots, ServerName: "localhost"}
}

// Pair connects a frame peer and a borrowed proxy connection over real UDP.
// For an origin peer the proxy is the QUIC client; otherwise it is the server.
func Pair(t *testing.T, ctx context.Context, origin bool) (*Peer, *quic.Conn) {
	t.Helper()
	listener, config := Listener(t)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	transport := &quic.Transport{Conn: socket}
	t.Cleanup(func() { _ = transport.Close() })
	client, err := transport.Dial(ctx, listener.Addr(), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0x100, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0x100, "") })
	if origin {
		return NewPeer(t, ctx, server), client
	}
	return NewPeer(t, ctx, client), server
}

// NewPeer observes incoming critical streams without hiding their control frames.
// Cleanup closes the connection and joins every stream reader.
func NewPeer(t *testing.T, ctx context.Context, conn *quic.Conn) *Peer {
	t.Helper()
	peer := &Peer{Conn: conn, Control: make(chan Frame, 16)}
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			stream, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			workers.Go(func() {
				kind, err := quicvarint.Read(quicvarint.NewReader(stream))
				if err != nil {
					return
				}
				if kind != 0 {
					_, _ = io.Copy(io.Discard, stream)
					return
				}
				for {
					frame, err := ReadFrame(stream)
					if err != nil {
						return
					}
					select {
					case peer.Control <- frame:
					case <-conn.Context().Done():
						return
					case <-ctx.Done():
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() { _ = conn.CloseWithError(0x100, ""); workers.Wait() })
	return peer
}

// Init sends SETTINGS and opens the QPACK encoder/decoder streams without FIN.
func (p *Peer) Init(t *testing.T, ctx context.Context) {
	t.Helper()
	for _, kind := range []uint64{0, 2, 3} {
		stream, err := p.Conn.OpenUniStreamSync(ctx)
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
}
