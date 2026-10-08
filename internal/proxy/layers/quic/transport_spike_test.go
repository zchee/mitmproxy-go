// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	quicgo "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

type spikeReplayConn struct {
	layer.PacketRecorder
	mu       sync.Mutex
	observed [][]byte
}

func (c *spikeReplayConn) ReadFrom(data []byte) (int, net.Addr, error) {
	n, peer, err := c.PacketRecorder.ReadFrom(data)
	if err == nil {
		c.mu.Lock()
		if len(c.observed) < 2 {
			c.observed = append(c.observed, bytes.Clone(data[:n]))
		}
		c.mu.Unlock()
	}
	return n, peer, err
}

func TestQUICPacketTransportReplay(t *testing.T) {
	// internal/h3's bootstrap contract covers ordinary UDP sockets; this row
	// proves sniffing and replay over the actual fixed-peer packet transport.
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	key, ca, err := certs.CreateCA("QUIC replay", "QUIC replay root", 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certs.DummyCert(key, ca, "two-datagram.example", []certs.GeneralName{certs.DNSName("two-datagram.example")}, "", "")
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
	clientTLS := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		NextProtos:       []string{"h3"},
		RootCAs:          roots,
		ServerName:       "two-datagram.example",
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
	tests := map[string]struct {
		wantSNI string
	}{
		"success: two Initials replay in arrival order": {wantSNI: "two-datagram.example"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener := packettransport.NewListener(ctx, serverSocket)
			defer func() { _ = listener.Close() }()
			clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = clientSocket.Close() }()
			clientTransport := quicgo.Transport{Conn: clientSocket}
			defer func() { _ = clientTransport.Close() }()
			clientDone := make(chan error, 1)
			var dialer sync.WaitGroup
			dialer.Go(func() {
				client, err := clientTransport.Dial(ctx, serverSocket.LocalAddr(), clientTLS, &quicgo.Config{
					Versions:          []quicgo.Version{quicgo.Version1},
					InitialPacketSize: 1200,
				})
				if err != nil {
					clientDone <- err
					return
				}
				if client.ConnectionState().TLS.NegotiatedProtocol != "h3" {
					clientDone <- fmt.Errorf("client did not negotiate h3")
					return
				}
				clientDone <- nil
				<-ctx.Done()
				_ = client.CloseWithError(0, "")
			})
			defer func() { cancel(); dialer.Wait() }()
			tuple, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			recorder := proxy.RecordPackets(tuple)
			deadline, _ := ctx.Deadline()
			if err := recorder.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			var parser tlsparse.QUICClientHelloParser
			var buffered [][]byte
			var hello *tlsparse.ClientHello
			buf := make([]byte, layer.MaxUDPPacketBytes)
			for hello == nil {
				n, _, err := recorder.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				buffered = append(buffered, bytes.Clone(buf[:n]))
				hello, err = parser.Feed(buf[:n])
				if err != nil {
					t.Fatal(err)
				}
				if len(buffered) > 2 {
					t.Fatal("hello required more than the two expected Initial datagrams")
				}
			}
			if len(buffered) != 2 {
				t.Fatalf("sniffed %d datagrams, want 2", len(buffered))
			}
			if diff := gocmp.Diff(tt.wantSNI, hello.SNI()); diff != "" {
				t.Fatalf("sniffed SNI (-want +got):\n%s", diff)
			}
			recorder.StopRecording()
			observed := &spikeReplayConn{PacketRecorder: recorder}
			serverTransport := quicgo.Transport{Conn: observed}
			defer func() { _ = serverTransport.Close() }()
			quicListener, err := serverTransport.Listen(serverTLS, &quicgo.Config{Versions: []quicgo.Version{quicgo.Version1}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = quicListener.Close() }()
			server, err := quicListener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.CloseWithError(0, "") }()
			if err := <-clientDone; err != nil {
				t.Fatal(err)
			}
			if server.ConnectionState().TLS.NegotiatedProtocol != "h3" {
				t.Fatal("server did not negotiate h3")
			}
			observed.mu.Lock()
			got := observed.observed
			observed.mu.Unlock()
			if diff := gocmp.Diff(buffered, got); diff != "" {
				t.Errorf("replayed packets (-want +got):\n%s", diff)
			}
		})
	}
}
