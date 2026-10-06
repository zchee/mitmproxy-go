// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type observedPacketReads struct {
	layer.PacketTransport
	read chan string
}

func (c observedPacketReads) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketTransport.ReadFrom(p)
	if err == nil {
		c.read <- string(p[:n])
	}
	return n, addr, err
}

func TestNextPacketLayerLateHookReply(t *testing.T) {
	conn, peer := acceptedPackets(t, []byte("foo"))
	read := make(chan string, 2)
	entered, release := make(chan struct{}), make(chan struct{})
	c := newSelector(t, nil, func(ctx context.Context, d *hookdata.NextLayer) error {
		close(entered)
		_, err := addon.Concurrent(ctx, func(ctx context.Context) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if string(d.DataClient) != "foo" {
			t.Errorf("late packet mutated hook view: %q", d.DataClient)
		}
		d.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		return err
	})
	c.Client, c.ClientPackets = nil, RecordPackets(observedPacketReads{PacketTransport: conn, read: read})
	done := startSelection(t, t.Context(), c)
	await(t, entered)
	if got := await(t, read); got != "foo" {
		t.Fatal(got)
	}
	if _, err := peer.Write([]byte("bar")); err != nil {
		t.Fatal(err)
	}
	if got := await(t, read); got != "bar" {
		t.Fatal(got)
	}
	close(release)
	requireSelection(t, done)
	if err := c.ClientPackets.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var window [8]byte
	for _, want := range []string{"foo", "bar"} {
		n, _, err := c.ClientPackets.ReadFrom(window[:])
		if err != nil || string(window[:n]) != want {
			t.Fatalf("replay = %q, %v; want %q", window[:n], err, want)
		}
	}
}

func TestNextPacketLayerServerGreeting(t *testing.T) {
	client, peer := acceptedPackets(t, nil)
	if _, _, err := client.ReadFrom(nil); err != nil {
		t.Fatal(err)
	}
	server, _ := acceptedPackets(t, []byte("ready"))
	c := newSelector(t, nil, func(_ context.Context, d *hookdata.NextLayer) error {
		if len(d.DataClient) != 0 || string(d.DataServer) != "ready" {
			t.Errorf("greeting = %q/%q", d.DataClient, d.DataServer)
		}
		d.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		return nil
	})
	c.Client, c.ClientPackets, c.ServerPackets = nil, RecordPackets(client), RecordPackets(server)
	requireSelection(t, startSelection(t, t.Context(), c))
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var window [8]byte
	for input, want := range map[layer.PacketRecorder]string{c.ClientPackets: "hello", c.ServerPackets: "ready"} {
		if err := input.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := input.ReadFrom(window[:])
		if err != nil || string(window[:n]) != want {
			t.Fatalf("replay = %q, %v; want %q", window[:n], err, want)
		}
	}
}

func TestNextPacketLayerInvalidStack(t *testing.T) {
	tests := map[string]struct{ stack hookdata.LayerStack }{
		"empty":          {stack: hookdata.LayerStack{}},
		"unknown":        {stack: hookdata.LayerStack{{Kind: "unregistered"}}},
		"top-level mode": {stack: hookdata.LayerStack{{Kind: hookdata.LayerRegular}}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, _ := acceptedPackets(t, nil)
			c := newSelector(t, nil, func(_ context.Context, d *hookdata.NextLayer) error { d.Layer = test.stack; return nil })
			c.Client, c.ClientPackets = nil, RecordPackets(conn)
			if result := await(t, startSelection(t, t.Context(), c)); result.err == nil || result.layer != nil {
				t.Fatalf("invalid selection = %+v", result)
			}
			if len(c.Data.Layers) != 0 {
				t.Fatal("failed build published a layer")
			}
		})
	}
}
