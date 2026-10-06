// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestHandlePacketsOpenOrigin(t *testing.T) {
	tests := map[string]struct{ fail bool }{"success": {}, "dial error": {fail: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			origin, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = origin.Close() }()
			conn, peer := acceptedPackets(t, []byte("request"))
			recorder := new(addontest.Recorder)
			bind := &bindAddon{t: t, ids: make(chan string, 1)}
			bind.run = func(ctx context.Context, c *layer.Context) error {
				if err := c.Do(ctx, func(context.Context) error {
					c.Data.Server.Address = addressOf(origin.LocalAddr())
					if test.fail {
						c.Data.Server.Sockname = &connection.Address{Host: "not-an-ip"}
					}
					return nil
				}); err != nil {
					return err
				}
				socket, actual, err := c.OpenPackets(ctx, c.Data.Server)
				if err != nil {
					return err
				}
				if actual != c.Data.Server || actual.Peername == nil || actual.Sockname == nil || actual.TimestampTCPSetup == nil {
					return errors.New("origin metadata missing")
				}
				buf := make([]byte, 32)
				n, _, err := c.ClientPackets.ReadFrom(buf)
				if err != nil {
					return err
				}
				if _, err := socket.WriteTo(buf[:n], nil); err != nil {
					return err
				}
				n, _, err = origin.ReadFrom(buf)
				if err != nil {
					return err
				}
				if diff := gocmp.Diff("request", string(buf[:n])); diff != "" {
					return errors.New(diff)
				}
				return nil
			}
			runner := newHookRunner(t, recorder, bind)
			h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: new(Connections)})
			if err != nil {
				t.Fatal(err)
			}
			if err := origin.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- h.HandlePackets(t.Context(), conn, "reverse:udp://"+origin.LocalAddr().String(), hookdata.LayerSpec{Kind: topKind})
			}()
			if err := await(t, done); (err != nil) != test.fail {
				t.Fatalf("HandlePackets error = %v, want failure %v", err, test.fail)
			}
			_ = peer.Close()
			var hooks []string
			for _, hook := range recorder.Hooks() {
				if strings.HasPrefix(hook, "server_") {
					hooks = append(hooks, hook)
				}
			}
			want := []string{"server_connect", "server_connected", "server_disconnected"}
			if test.fail {
				want = []string{"server_connect", "server_connect_error"}
			}
			if diff := gocmp.Diff(want, hooks); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestHandlePacketsIdleExpiry(t *testing.T) {
	conn, _ := acceptedPackets(t, nil)
	entered := make(chan struct{})
	bind := &bindAddon{t: t, ids: make(chan string, 1), run: func(ctx context.Context, c *layer.Context) error {
		buf := make([]byte, 1)
		if _, _, err := c.ClientPackets.ReadFrom(buf); err != nil {
			return err
		}
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}}
	runner := newHookRunner(t, bind)
	registry := new(Connections)
	h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: registry})
	if err != nil {
		t.Fatal(err)
	}
	clock := new(manualClock)
	h.clock = clock
	done := make(chan error, 1)
	go func() {
		done <- h.HandlePackets(t.Context(), conn, "reverse:udp://127.0.0.1:443", hookdata.LayerSpec{Kind: topKind})
	}()
	await(t, entered)
	clock.advance(20*time.Second - time.Nanosecond)
	if conn.Context().Err() != nil {
		t.Fatal("tuple expired before idle boundary")
	}
	clock.advance(time.Nanosecond)
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if conn.Context().Err() == nil || registry.Len() != 0 {
		t.Fatal("expired tuple remains live")
	}
}
