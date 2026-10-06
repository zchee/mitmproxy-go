// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestNextPacketLayerReplay(t *testing.T) {
	tests := map[string]struct{ packets [][]byte }{
		"empty packet chooses immediately": {packets: [][]byte{nil}},
		"two packets remain separate":      {packets: [][]byte{[]byte("foo"), []byte("bar")}},
		"large packet is not truncated":    {packets: [][]byte{bytes.Repeat([]byte{'x'}, 60<<10), []byte("tail")}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := acceptedPackets(t, nil)
			if _, _, err := conn.ReadFrom(nil); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetWriteBuffer(1 << 20); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write(test.packets[0]); err != nil {
				t.Fatal(err)
			}
			asked := make(chan []byte, len(test.packets))
			count := 0
			c := newSelector(t, nil, func(_ context.Context, d *hookdata.NextLayer) error {
				count++
				if cap(d.DataClient) != len(d.DataClient) {
					t.Errorf("unclipped view")
				}
				asked <- bytes.Clone(d.DataClient)
				if count == len(test.packets) {
					d.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
				}
				return nil
			})
			c.Client = nil
			c.ClientPackets, c.RecordPackets = RecordPackets(conn), RecordPackets
			c.Data.Client.TransportProtocol, c.Data.Server.TransportProtocol = connection.UDP, connection.UDP
			done := startSelection(t, t.Context(), c)
			var accumulated []byte
			for i, packet := range test.packets {
				if i != 0 {
					if _, err := peer.Write(packet); err != nil {
						t.Fatal(err)
					}
				}
				accumulated = append(accumulated, packet...)
				if got := await(t, asked); !bytes.Equal(accumulated, got) {
					t.Fatalf("sniffed %d bytes, want %d", len(got), len(accumulated))
				}
			}
			requireSelection(t, done)
			if err := c.ClientPackets.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			window := make([]byte, layer.MaxUDPPacketBytes)
			for _, packet := range test.packets {
				n, addr, err := c.ClientPackets.ReadFrom(window)
				if err != nil {
					t.Fatal(err)
				}
				if addr.String() != peer.LocalAddr().String() {
					t.Fatal("replay lost address")
				}
				if diff := gocmp.Diff(string(packet), string(window[:n])); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestNextPacketLayerCancellation(t *testing.T) {
	conn, _ := acceptedPackets(t, []byte("first"))
	asked := make(chan struct{}, 1)
	c := newSelector(t, nil, func(context.Context, *hookdata.NextLayer) error { asked <- struct{}{}; return nil })
	c.Client = nil
	c.ClientPackets = RecordPackets(conn)
	ctx, cancel := context.WithCancel(t.Context())
	done := startSelection(t, ctx, c)
	await(t, asked)
	cancel()
	if result := await(t, done); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("cancel result = %v", result.err)
	}
	// Cancellation of selection interrupts only its reader, not the shared tuple.
	if err := conn.Context().Err(); err != nil {
		t.Fatalf("selector closed tuple: %v", err)
	}
}

func TestNextPacketLayerEmptyBound(t *testing.T) {
	conn, peer := acceptedPackets(t, nil)
	asked := make(chan struct{})
	c := newSelector(t, nil, func(context.Context, *hookdata.NextLayer) error { asked <- struct{}{}; return nil })
	c.Client = nil
	c.ClientPackets = RecordPackets(conn)
	done := startSelection(t, t.Context(), c)
	for i := range layer.PacketQueueCapacity {
		if i != 0 {
			if _, err := peer.Write(nil); err != nil {
				t.Fatal(err)
			}
		}
		await(t, asked)
	}
	if result := await(t, done); !errors.Is(result.err, layer.ErrPacketOverflow) {
		t.Fatalf("bound result = %v", result.err)
	}
}
