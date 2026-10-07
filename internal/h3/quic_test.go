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
	quic "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/certs"
)

func TestQUICContract(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	key, ca, err := certs.CreateCA("QUIC contract", "QUIC contract root", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "localhost", []certs.GeneralName{certs.DNSName("localhost")}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.X509())
	serverTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.X509().Raw, ca.X509().Raw},
			PrivateKey:  key,
		}},
	}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, RootCAs: roots, ServerName: "localhost"}
	tests := map[string]struct {
		serverInitiated bool
		closeCode       uint64
	}{
		"client opens bidirectional stream": {closeCode: 0x100},
		"server opens bidirectional stream": {serverInitiated: true, closeCode: 0x10c},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := serverSocket.Close(); err != nil {
					t.Errorf("close server socket: %v", err)
				}
			}()
			serverTransport := newQUICTransport(serverSocket)
			defer func() {
				if err := serverTransport.close(); err != nil {
					t.Errorf("close server transport: %v", err)
				}
			}()
			listener, err := serverTransport.listen(serverTLS, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := listener.close(); err != nil {
					t.Errorf("close listener: %v", err)
				}
			}()
			clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := clientSocket.Close(); err != nil {
					t.Errorf("close client socket: %v", err)
				}
			}()
			clientTransport := newQUICTransport(clientSocket)
			defer func() {
				if err := clientTransport.close(); err != nil {
					t.Errorf("close client transport: %v", err)
				}
			}()
			client, err := clientTransport.dial(ctx, serverSocket.LocalAddr(), clientTLS, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := client.closeWithError(0x100); err != nil {
					t.Errorf("close client connection: %v", err)
				}
			}()
			server, err := listener.accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := server.closeWithError(0x100); err != nil {
					t.Errorf("close server connection: %v", err)
				}
			}()
			for _, peer := range []*quicConnection{client, server} {
				if got := peer.conn.ConnectionState().TLS.NegotiatedProtocol; got != "h3" {
					t.Fatalf("negotiated ALPN = %q, want h3", got)
				}
			}
			opener, acceptor := client, server
			if test.serverInitiated {
				opener, acceptor = server, client
			}
			stream, err := opener.openStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			deadline, _ := ctx.Deadline()
			if err := stream.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			payload := []byte("ordered QUIC stream payload")
			if _, err := stream.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			incoming, err := acceptor.acceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := incoming.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if stream.StreamID() != incoming.StreamID() {
				t.Fatalf("stream identities differ: opened %d, accepted %d", stream.StreamID(), incoming.StreamID())
			}
			got, err := io.ReadAll(incoming)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(payload, got); diff != "" {
				t.Fatalf("forward payload (-want +got):\n%s", diff)
			}
			reply := []byte("reverse stream payload")
			if _, err := incoming.Write(reply); err != nil {
				t.Fatal(err)
			}
			if err := incoming.Close(); err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(stream)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(reply, got); diff != "" {
				t.Fatalf("reverse payload (-want +got):\n%s", diff)
			}
			uni, err := opener.openUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := uni.SetWriteDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if _, err := uni.Write([]byte{0}); err != nil {
				t.Fatal(err)
			}
			if err := uni.Close(); err != nil {
				t.Fatal(err)
			}
			receivedUni, err := acceptor.acceptUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := receivedUni.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(receivedUni)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]byte{0}, got); diff != "" {
				t.Fatalf("unidirectional payload (-want +got):\n%s", diff)
			}
			if err := opener.closeWithError(test.closeCode); err != nil {
				t.Fatal(err)
			}
			_, err = acceptor.acceptStream(ctx)
			appErr, ok := errors.AsType[*quic.ApplicationError](err)
			if !ok || !appErr.Remote || uint64(appErr.ErrorCode) != test.closeCode || appErr.ErrorMessage != "" {
				t.Fatalf("peer close = %v, want remote application code %#x and no wire diagnostic", err, test.closeCode)
			}
		})
	}
}
