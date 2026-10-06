// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

func acceptedPackets(t *testing.T, first []byte) (*packettransport.TupleConn, *net.UDPConn) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := packettransport.NewListener(t.Context(), socket)
	t.Cleanup(func() { _ = listener.Close() })
	peer, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.Write(first); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return conn, peer
}

func TestHandlePacketsLifecycle(t *testing.T) {
	tests := map[string]struct{ first []byte }{
		"empty datagram":    {},
		"ordinary datagram": {first: []byte("packet")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := acceptedPackets(t, test.first)
			recorder := new(addontest.Recorder)
			bind := &bindAddon{t: t, ids: make(chan string, 1)}
			bind.run = func(ctx context.Context, c *layer.Context) error {
				if c.Client != nil || c.ClientPackets == nil || c.RecordPackets == nil || c.OpenPackets == nil || c.Clock == nil {
					return errors.New("missing packet-only context")
				}
				if c.Data.Client.TransportProtocol != connection.UDP || c.Data.Server.TransportProtocol != connection.UDP {
					return errors.New("wrong transport metadata")
				}
				buf := make([]byte, 64)
				n, addr, err := c.ClientPackets.ReadFrom(buf)
				if err != nil {
					return err
				}
				if diff := gocmp.Diff(string(test.first), string(buf[:n])); diff != "" {
					return errors.New(diff)
				}
				_, err = c.ClientPackets.WriteTo(buf[:n], addr)
				return err
			}
			runner := newHookRunner(t, recorder, bind)
			registry := new(Connections)
			h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: registry})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- h.HandlePackets(t.Context(), conn, "reverse:udp://127.0.0.1:9999", hookdata.LayerSpec{Kind: topKind})
			}()
			if err := peer.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, err := peer.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(string(test.first), string(buf[:n])); diff != "" {
				t.Fatal(diff)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff([]string{"client_connected", "client_disconnected"}, clientLifecycleHooks(recorder)); diff != "" {
				t.Fatal(diff)
			}
			if registry.Len() != 0 {
				t.Fatal("packet connection remains registered")
			}
		})
	}
}

func TestPacketOriginClose(t *testing.T) {
	tests := map[string]struct {
		cancelLifetime bool
		concurrent     bool
	}{
		"repeated close":                    {},
		"canceled lifetime":                 {cancelLifetime: true},
		"concurrent close":                  {concurrent: true},
		"cancellation and concurrent close": {cancelLifetime: true, concurrent: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			origin, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = origin.Close() })
			lifetime, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			srv := connection.NewServer(addressOf(origin.LocalAddr()))
			srv.TransportProtocol = connection.UDP
			conn, err := dialPacketServer(t.Context(), lifetime, srv, net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if test.cancelLifetime {
				cancel()
			}
			count := 2
			if test.concurrent {
				count = 16
			}
			results := make(chan error, count)
			var workers sync.WaitGroup
			for range count {
				if test.concurrent {
					workers.Go(func() { results <- conn.Close() })
				} else {
					results <- conn.Close()
				}
			}
			workers.Wait()
			close(results)
			for err := range results {
				if err != nil {
					t.Errorf("close origin: %v", err)
				}
			}
			if conn.Context().Err() == nil {
				t.Fatal("closed origin lifetime remains active")
			}
			if _, err := conn.WriteTo([]byte("closed"), nil); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after close = %v, want net.ErrClosed", err)
			}
		})
	}
}

func TestPacketDialer(t *testing.T) {
	origin, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = origin.Close() }()
	tests := map[string]struct {
		source   *connection.Address
		protocol connection.TransportProtocol
		fails    bool
	}{
		"default source":  {protocol: connection.UDP},
		"explicit source": {protocol: connection.UDP, source: &connection.Address{Host: "127.0.0.1"}},
		"invalid source":  {protocol: connection.UDP, source: &connection.Address{Host: "not-an-ip"}, fails: true},
		"reject TCP":      {protocol: connection.TCP, fails: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			srv := connection.NewServer(addressOf(origin.LocalAddr()))
			srv.TransportProtocol, srv.Sockname = test.protocol, test.source
			conn, err := dialPacketServer(t.Context(), t.Context(), srv, net.Dialer{})
			if test.fails {
				if err == nil {
					_ = conn.Close()
					t.Fatal("expected rejected dial")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := origin.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.WriteTo(nil, nil); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 8)
			n, peer, err := origin.ReadFrom(buf)
			if err != nil || n != 0 {
				t.Fatalf("empty datagram = %d, %v", n, err)
			}
			if _, err := origin.WriteTo([]byte("reply"), peer); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			n, _, err = conn.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("reply", string(buf[:n])); diff != "" {
				t.Fatal(diff)
			}
			other := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
			if _, err := conn.WriteTo([]byte("wrong peer"), other); err == nil {
				t.Fatal("accepted write outside fixed tuple")
			}
		})
	}
}
