// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

func dtlsTestPair(t *testing.T) (*dtlsPackets, *dtls.Conn, *packettransport.Listener) {
	t.Helper()
	tlsServer, tlsClient := tlsConfigs(t)
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := packettransport.NewListener(t.Context(), socket)
	t.Cleanup(func() { _ = listener.Close() })
	peerSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peerSocket.Close() })
	peer, err := dtls.Client(peerSocket, listener.LocalAddr(), &dtls.Config{RootCAs: tlsClient.RootCAs, ServerName: tlsClient.ServerName}) //nolint:staticcheck // Exercise the frozen packet constructor used by TLS hooks.
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	peerDone := make(chan error, 1)
	go func() { peerDone <- peer.HandshakeContext(ctx) }()
	tuple, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	session, err := dtls.Server(tuple, tuple.RemoteAddr(), &dtls.Config{Certificates: tlsServer.Certificates}) //nolint:staticcheck // Exercise the frozen packet constructor used by TLS hooks.
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if err := session.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := await(t, peerDone); err != nil {
		t.Fatal(err)
	}
	return &dtlsPackets{Conn: session, raw: tuple}, peer, listener
}

func TestDTLSPacketAdapter(t *testing.T) {
	tests := map[string]struct {
		payload []byte
		size    int
	}{
		"success: application datagram": {payload: []byte("hello datagram"), size: 64},
		"success: empty datagram":       {payload: []byte{}, size: 64},
		"success: truncation discards":  {payload: []byte("truncate me"), size: 3},
		"success: zero read buffer":     {payload: []byte("discard all"), size: 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			packets, peer, _ := dtlsTestPair(t)
			if _, err := peer.Write(tt.payload); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, tt.size)
			n, addr, err := packets.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.payload[:min(tt.size, len(tt.payload))], buf[:n]); diff != "" {
				t.Fatal(diff)
			}
			if addr.String() != peer.LocalAddr().String() {
				t.Fatalf("packet peer = %v, want %v", addr, peer.LocalAddr())
			}
			if _, err := peer.Write([]byte("next")); err != nil {
				t.Fatal(err)
			}
			n, _, err = packets.ReadFrom(make([]byte, 32))
			if err != nil || n != 4 {
				t.Fatalf("truncated remainder leaked into next packet: %d, %v", n, err)
			}
			if _, err := packets.WriteTo([]byte("reply"), nil); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 32)
			n, err = peer.Read(reply)
			if err != nil || !bytes.Equal(reply[:n], []byte("reply")) {
				t.Fatalf("reply = %q, %v", reply[:n], err)
			}
			if _, err := packets.WriteTo([]byte("wrong peer"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}); err == nil {
				t.Fatal("DTLS packet changed fixed peer")
			}
		})
	}
}

func TestDTLSPacketCloseIsolatesTuple(t *testing.T) {
	packets, _, listener := dtlsTestPair(t)
	if err := packets.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if !errors.Is(packets.Context().Err(), context.Canceled) {
		t.Fatal("DTLS close did not cancel underlying tuple")
	}
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	if _, err := other.WriteTo([]byte("still alive"), listener.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	tuple, err := listener.Accept(t.Context())
	if err != nil {
		t.Fatalf("DTLS close affected listener: %v", err)
	}
	buf := make([]byte, 32)
	n, _, err := tuple.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "still alive" {
		t.Fatalf("unrelated tuple packet = %q, %v", buf[:n], err)
	}
}
