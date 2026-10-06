// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestNextPacketHeadDeadline(t *testing.T) {
	tests := map[string]struct{ trickle, complete bool }{
		"silence expires at the boundary":        {},
		"trickled packets do not reset deadline": {trickle: true},
		"completion stops pending expiry":        {trickle: true, complete: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := acceptedPackets(t, []byte{0x16, 0xfe, 0xfd})
			clock := new(manualClock)
			asked := make(chan struct{}, 2)
			var calls atomic.Int32
			c := newSelector(t, nil, func(_ context.Context, d *hookdata.NextLayer) error {
				calls.Add(1)
				if test.complete && len(d.DataClient) == 4 {
					d.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
				}
				asked <- struct{}{}
				return nil
			})
			c.Client, c.ClientPackets, c.Clock = nil, RecordPackets(conn), layerClock{clock}
			done := startSelection(t, t.Context(), c)
			await(t, asked)
			clock.advance(19 * time.Second)
			if test.trickle {
				if _, err := peer.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
				await(t, asked)
			}
			if test.complete {
				requireSelection(t, done)
				clock.advance(time.Hour)
				if err := conn.Context().Err(); err != nil {
					t.Fatalf("timer closed completed tuple: %v", err)
				}
				clock.mu.Lock()
				active := clock.timers[0].active
				clock.mu.Unlock()
				if active {
					t.Fatal("completed selector retained a timer")
				}
				return
			}
			clock.advance(11*time.Second - time.Nanosecond)
			select {
			case result := <-done:
				t.Fatalf("expired before boundary: %+v", result)
			default:
			}
			clock.advance(time.Nanosecond)
			result := await(t, done)
			var timeout packetHeadTimeout
			if !errors.As(result.err, &timeout) || !timeout.Timeout() || result.layer != nil {
				t.Fatalf("expiry result = %+v", result)
			}
			wantCalls := int32(1)
			if test.trickle {
				wantCalls++
			}
			if calls.Load() != wantCalls {
				t.Fatalf("hooks after expiry: got %d, want %d", calls.Load(), wantCalls)
			}
			if len(c.Data.Layers) != 0 {
				t.Fatal("expiry published a layer")
			}
		})
	}
}

func TestNextPacketHeadDeadlineDuringHook(t *testing.T) {
	conn, _ := acceptedPackets(t, []byte{0x16, 0xfe, 0xfd})
	clock := new(manualClock)
	entered := make(chan struct{})
	c := newSelector(t, nil, func(ctx context.Context, d *hookdata.NextLayer) error {
		close(entered)
		_, err := addon.Concurrent(ctx, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
		d.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		return err
	})
	c.Client, c.ClientPackets, c.Clock = nil, RecordPackets(conn), layerClock{clock}
	done := startSelection(t, t.Context(), c)
	await(t, entered)
	clock.advance(layer.HeadReadTimeout)
	result := await(t, done)
	var timeout packetHeadTimeout
	if !errors.As(result.err, &timeout) || result.layer != nil {
		t.Fatalf("in-hook expiry = %+v", result)
	}
}
