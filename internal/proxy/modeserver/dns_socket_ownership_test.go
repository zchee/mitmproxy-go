// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/netutil/freeport"
)

func TestDNSSocketOwnership(t *testing.T) {
	failure := errors.New("injected listener setup failure")
	tests := map[string]struct {
		stage        string
		wantTCP      int
		wantUDP      int
		wantCanceled bool
	}{
		"error: before socket transfer":        {stage: "factory lookup"},
		"error: canceled before transfer":      {stage: "canceled", wantCanceled: true},
		"error: after TCP transfer":            {stage: "UDP", wantTCP: 1},
		"error: after both socket transfers":   {stage: "activation", wantTCP: 1, wantUDP: 1},
		"success: Start and Stop release pair": {stage: "Stop", wantTCP: 1, wantUDP: 1},
		"success: cancellation releases pair":  {stage: "cancel", wantTCP: 1, wantUDP: 1},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			cfg, _, _ := fixture(t)
			instance := makeInstance(t, "reverse:dns://127.0.0.1:53@127.0.0.1:0", cfg)
			pair := prepareDNSSockets(t, instance)
			tcp, udp := pair.tcp, pair.udp
			tcpTransfers, udpTransfers := 0, 0
			instance.listenTCP = func(ctx context.Context, network, address string) (net.Listener, error) {
				listener, err := pair.listenTCP(ctx, network, address)
				if err == nil {
					tcpTransfers++
				}
				return listener, err
			}
			instance.listenUDP = func(ctx context.Context, network, address string) (net.PacketConn, error) {
				if test.stage == "UDP" {
					return nil, failure
				}
				socket, err := pair.listenUDP(ctx, network, address)
				if err == nil {
					udpTransfers++
				}
				return socket, err
			}
			key := ListenerKey{Scheme: "dns", Transport: connection.UDP}
			switch test.stage {
			case "factory lookup":
				delete(instance.factories, key)
			case "activation":
				instance.factories[key] = func(_ context.Context, socket net.PacketConn, _ PacketHandler) (io.Closer, error) {
					if socket != udp {
						t.Error("factory did not receive the acquired UDP socket")
					}
					return nil, failure
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.wantCanceled {
				cancel()
			}
			err := pair.start(ctx, instance)
			success := test.stage == "Stop" || test.stage == "cancel"
			if (err == nil) != success {
				t.Fatalf("Start error = %v, want success %t", err, success)
			}
			if test.wantCanceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("Start lost cancellation: %v", err)
			}
			if (test.stage == "UDP" || test.stage == "activation") && !errors.Is(err, failure) {
				t.Fatalf("Start lost setup cause: %v", err)
			}
			if diff := gocmp.Diff([]int{test.wantTCP, test.wantUDP}, []int{tcpTransfers, udpTransfers}); diff != "" {
				t.Fatalf("socket transfers (-want +got):\n%s", diff)
			}
			if pair.tcp != nil || pair.udp != nil {
				t.Fatal("fixture retained transferred or closed socket references")
			}
			if test.stage == "cancel" {
				cancel()
				_ = udp.SetReadDeadline(time.Now().Add(time.Second))
				var buf [1]byte
				if _, _, err := udp.ReadFrom(buf[:]); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("cancellation did not close UDP socket: %v", err)
				}
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
				t.Fatal("failed or stopped instance retained listener state")
			}
			assertDNSSocketsClosed(t, tcp, udp)
			if listener, err := pair.listenTCP(t.Context(), "tcp", pair.tcpRequest); listener != nil || err == nil {
				t.Fatalf("retry returned a stale TCP handle: %v, %v", listener, err)
			}
			if socket, err := pair.listenUDP(t.Context(), "udp", pair.address); socket != nil || err == nil {
				t.Fatalf("retry returned a stale UDP handle: %v, %v", socket, err)
			}
			instance.factories = registeredFactories(nil)
			startDNSInstance(t, instance)
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertDNSSocketsClosed(t *testing.T, tcp net.Listener, udp *net.UDPConn) {
	t.Helper()
	listener, ok := tcp.(*net.TCPListener)
	if !ok {
		t.Fatalf("acquired TCP socket type = %T", tcp)
	}
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	_ = udp.SetReadDeadline(time.Now().Add(time.Second))
	if client, err := tcp.Accept(); client != nil || !errors.Is(err, net.ErrClosed) {
		if client != nil {
			_ = client.Close()
		}
		t.Fatalf("TCP socket remains open: %v", err)
	}
	var buf [1]byte
	if _, _, err := udp.ReadFrom(buf[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("UDP socket remains open: %v", err)
	}
}

func TestDNSSocketSeamValidation(t *testing.T) {
	tests := map[string]struct {
		network string
		address string
		udp     bool
	}{
		"error: TCP network mismatch": {network: "tcp6", address: "127.0.0.1:0"},
		"error: TCP address mismatch": {network: "tcp", address: "127.0.0.2:0"},
		"error: UDP network mismatch": {network: "udp6", udp: true},
		"error: UDP address mismatch": {network: "udp", address: "127.0.0.2:0", udp: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			instance := makeInstance(t, "dns@127.0.0.1:0", cfg)
			pair := prepareDNSSockets(t, instance)
			tcp, udp := pair.tcp, pair.udp
			if test.udp {
				address := test.address
				if address == "" {
					address = pair.address
				}
				if socket, err := pair.listenUDP(t.Context(), test.network, address); socket != nil || err == nil {
					t.Fatalf("invalid UDP seam accepted: %v, %v", socket, err)
				}
			} else if listener, err := pair.listenTCP(t.Context(), test.network, test.address); listener != nil || err == nil {
				t.Fatalf("invalid TCP seam accepted: %v, %v", listener, err)
			}
			if pair.tcp != tcp || pair.udp != udp {
				t.Fatal("invalid seam invocation consumed a socket")
			}
			pair.close()
			assertDNSSocketsClosed(t, tcp, udp)
		})
	}
}

func TestDNSSocketAcquisitionErrors(t *testing.T) {
	tests := map[string]struct{ canceled bool }{
		"error: fixed occupied pair":  {},
		"error: canceled acquisition": {canceled: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			owned := acquireDNSSockets(t, "tcp4", "127.0.0.1:0")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.canceled {
				cancel()
			}
			tcp, udp, err := freeport.ListenPair(ctx, "tcp4", owned.address)
			if tcp != nil || udp != nil || err == nil {
				t.Fatalf("failed acquisition returned handles: %v, %v, %v", tcp, udp, err)
			}
			if _, ok := errors.AsType[*net.OpError](err); !ok {
				t.Fatalf("acquisition error lacks operation context: %T", err)
			}
			if test.canceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("acquisition lost cancellation: %v", err)
			}
			owned.close()
			cfg, _, _ := fixture(t)
			startDNSInstance(t, makeInstance(t, "dns@127.0.0.1:0", cfg))
		})
	}
}
