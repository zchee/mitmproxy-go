// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/connection"
)

func listenLoopback(t *testing.T) (*connection.Server, *net.TCPListener) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	return connection.NewServer(&connection.Address{Host: addr.IP.String(), Port: addr.Port}), listener
}

func TestDialServer(t *testing.T) {
	tests := map[string]struct{ source *connection.Address }{
		"default":   {},
		"source IP": {source: &connection.Address{Host: "127.0.0.1"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			srv, listener := listenLoopback(t)
			srv.Sockname = tt.source
			conn, err := NewDialer(net.Dialer{})(t.Context(), srv)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			peer, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if got := conn.LocalAddr().(*net.TCPAddr).IP.String(); tt.source != nil && got != tt.source.Host {
				t.Errorf("source IP = %q, want %q", got, tt.source.Host)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("peer after write-half-close: n=%d err=%v", n, err)
			}
			written := make(chan error, 1)
			go func() {
				_, err := peer.Write([]byte("x"))
				if err == nil {
					err = peer.CloseWrite()
				}
				written <- err
			}()
			requireReplay(t, conn, []byte("x"))
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDialServerRejects(t *testing.T) {
	listening, _ := listenLoopback(t)
	occupied, _ := listenLoopback(t)
	tests := map[string]struct{ prepare func(*connection.Server) }{
		"no address": {prepare: func(srv *connection.Server) { srv.Address = nil }},
		"empty host": {prepare: func(srv *connection.Server) { srv.Address.Host = "" }},
		"invalid source address": {prepare: func(srv *connection.Server) {
			srv.Sockname = &connection.Address{Host: "server.invalid"}
		}},
		"occupied source port": {prepare: func(srv *connection.Server) {
			srv.Sockname = occupied.Address
		}},
		"invalid source port with wildcard host": {prepare: func(srv *connection.Server) {
			srv.Sockname = &connection.Address{Port: -1}
		}},
		"non-tcp transport": {prepare: func(srv *connection.Server) { srv.TransportProtocol = connection.UDP }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			srv := listening.Clone()
			tt.prepare(srv)
			conn, err := NewDialer(net.Dialer{})(t.Context(), srv)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatal("invalid dial configuration accepted")
			}
		})
	}
}

func TestDialServerHonoursCancellation(t *testing.T) {
	srv, _ := listenLoopback(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	conn, err := NewDialer(net.Dialer{})(ctx, srv)
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial: %v, want context.Canceled", err)
	}
}
