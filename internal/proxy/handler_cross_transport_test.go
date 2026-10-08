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

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestHandlerCrossTransportAcquisition(t *testing.T) {
	tests := map[string]struct{ packets bool }{
		"TCP client opens packet origin": {},
		"UDP client opens byte origin":   {packets: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			recorder := new(addontest.Recorder)
			var opened layer.PacketTransport
			var byteOrigin layer.Conn
			var captured *layer.Context
			bind := &bindAddon{t: t, ids: make(chan string, 1)}
			bind.run = func(ctx context.Context, c *layer.Context) error {
				captured = c
				if c.Pool == nil || c.Record == nil || c.OpenPackets == nil || c.RecordPackets == nil {
					return errors.New("accepted client lacks cross-transport acquisition or recording")
				}
				if tt.packets {
					origin, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						return err
					}
					defer func() { _ = origin.Close() }()
					server := connection.NewServer(addressOf(origin.Addr()))
					byteOrigin, _, err = c.Pool.Open(ctx, server, layer.OpenOptions{Reuse: true})
					if err != nil {
						return err
					}
					peer, err := origin.Accept()
					if err != nil {
						return err
					}
					defer func() { _ = peer.Close() }()
					if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
						return err
					}
					if err := byteOrigin.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
						return err
					}
					stream := c.Record(byteOrigin)
					if _, err := stream.Write([]byte("byte request")); err != nil {
						return err
					}
					buf := make([]byte, len("byte request"))
					if _, err := io.ReadFull(peer, buf); err != nil {
						return err
					}
					if diff := gocmp.Diff("byte request", string(buf)); diff != "" {
						return errors.New(diff)
					}
					if _, err := peer.Write([]byte("byte reply")); err != nil {
						return err
					}
					buf = make([]byte, len("byte reply"))
					if _, err := io.ReadFull(stream, buf); err != nil {
						return err
					}
					if diff := gocmp.Diff("byte reply", string(buf)); diff != "" {
						return errors.New(diff)
					}
					return nil
				}
				origin, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					return err
				}
				defer func() { _ = origin.Close() }()
				if err := origin.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					return err
				}
				server := connection.NewServer(addressOf(origin.LocalAddr()))
				server.TransportProtocol = connection.UDP
				opened, _, err = c.OpenPackets(ctx, server)
				if err != nil {
					return err
				}
				transport := c.RecordPackets(opened)
				if _, err := transport.WriteTo([]byte("packet request"), nil); err != nil {
					return err
				}
				buf := make([]byte, 64)
				n, peer, err := origin.ReadFrom(buf)
				if err != nil {
					return err
				}
				if diff := gocmp.Diff("packet request", string(buf[:n])); diff != "" {
					return errors.New(diff)
				}
				if _, err := origin.WriteTo([]byte("packet reply"), peer); err != nil {
					return err
				}
				n, _, err = transport.ReadFrom(buf)
				if err != nil {
					return err
				}
				if diff := gocmp.Diff("packet reply", string(buf[:n])); diff != "" {
					return errors.New(diff)
				}
				return nil
			}
			runner := newHookRunner(t, recorder, bind)
			registry := new(Connections)
			h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: registry})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			if tt.packets {
				conn, peer := acceptedPackets(t, []byte("client packet"))
				defer func() { _ = peer.Close() }()
				go func() {
					done <- h.HandlePackets(ctx, conn, "reverse:udp://example.test:443", hookdata.LayerSpec{Kind: topKind})
				}()
			} else {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = listener.Close() }()
				peer, err := net.Dial("tcp4", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = peer.Close() }()
				conn, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				go func() { done <- h.Handle(ctx, conn, "regular", hookdata.LayerSpec{Kind: topKind}) }()
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			if registry.Len() != 0 {
				t.Fatal("completed client retained its connection registry entry")
			}
			server := connection.NewServer(&connection.Address{Host: "127.0.0.1", Port: 1})
			if tt.packets {
				if _, err := byteOrigin.Write([]byte("late")); err == nil {
					t.Fatal("byte origin survived owning packet client")
				}
				if _, _, err := captured.Pool.Open(t.Context(), server, layer.OpenOptions{}); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("late byte acquisition = %v", err)
				}
			} else {
				if opened.Context().Err() == nil {
					t.Fatal("packet origin survived owning stream client")
				}
				server.TransportProtocol = connection.UDP
				if _, _, err := captured.OpenPackets(t.Context(), server); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("late packet acquisition = %v", err)
				}
			}
			var hooks []string
			for _, hook := range recorder.Hooks() {
				if hook == "server_connect" || hook == "server_connected" || hook == "server_disconnected" {
					hooks = append(hooks, hook)
				}
			}
			if diff := gocmp.Diff([]string{"server_connect", "server_connected", "server_disconnected"}, hooks); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
