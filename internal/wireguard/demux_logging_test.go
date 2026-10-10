// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/device"
)

type gatedDemuxLogHandler struct {
	slog.Handler
	entered chan struct{}
	release chan struct{}
	records chan slog.Record
	gated   atomic.Bool
}

func (h *gatedDemuxLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *gatedDemuxLogHandler) Handle(_ context.Context, record slog.Record) error {
	h.records <- record.Clone()
	if h.gated.CompareAndSwap(false, true) {
		close(h.entered)
		<-h.release
	}
	return nil
}

// TestSocketDemuxDropLogging reproduces logger callbacks blocking registration
// on the parent, and preserves the drop counter and power-of-two log fields.
func TestSocketDemuxDropLogging(t *testing.T) {
	tests := map[string]struct {
		kind       uint32
		peers      int
		register   bool
		full       bool
		malformed  bool
		wantDrops  uint64
		wantCounts []uint64
	}{
		"success: unknown receiver unlocks before logging":          {kind: device.MessageTransportType, peers: 1, wantDrops: 1, wantCounts: []uint64{1}},
		"success: initiation fanout captures every crossing":        {kind: device.MessageInitiationType, peers: 5, full: true, wantDrops: 5, wantCounts: []uint64{1, 2, 4}},
		"success: known receiver full queue unlocks before logging": {kind: device.MessageTransportType, peers: 1, register: true, full: true, wantDrops: 1, wantCounts: []uint64{1}},
		"success: malformed packet preserves pre-lock logging":      {peers: 1, malformed: true, wantDrops: 1, wantCounts: []uint64{1}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			handler := &gatedDemuxLogHandler{Handler: slog.DiscardHandler, entered: make(chan struct{}), release: make(chan struct{}), records: make(chan slog.Record, 8)}
			demux := newSocketDemux(nil, test.peers, slog.New(handler))
			if test.register {
				demux.register(demuxTestPacket(device.MessageInitiationType, 42, 0), 0)
			}
			if test.full {
				for _, queue := range demux.queues {
					for range cap(queue) {
						queue <- encryptedDatagram{}
					}
				}
			}
			packet := demuxTestPacket(test.kind, 0, 42)
			if test.malformed {
				packet = nil
			}
			dispatched := make(chan struct{})
			registered := make(chan struct{})
			go func() {
				demux.dispatch(packet, netip.AddrPort{})
				close(dispatched)
			}()
			unblock := sync.OnceFunc(func() { close(handler.release) })
			t.Cleanup(func() {
				unblock()
				<-dispatched
				<-registered
			})
			select {
			case <-handler.entered:
			case <-time.After(5 * time.Second):
				// Keep cleanup joinable even when dispatch never logs.
				close(registered)
				t.Fatal("drop logger did not enter its handler")
			}
			go func() {
				demux.register(demuxTestPacket(device.MessageInitiationType, 73, 0), 0)
				close(registered)
			}()
			select {
			case <-registered:
			case <-time.After(time.Second):
				t.Fatal("registration blocked while the drop log handler was gated")
			}
			if got := demux.dropped.Load(); got != test.wantDrops {
				t.Errorf("drop total while logging is gated = %d, want %d", got, test.wantDrops)
			}
			// A concurrent pre-lock drop must not alter the captured fanout logs.
			demux.dispatch(nil, netip.AddrPort{})
			if got := demux.dropped.Load(); got != test.wantDrops+1 {
				t.Errorf("drop total after malformed packet = %d, want %d", got, test.wantDrops+1)
			}
			unblock()
			<-dispatched
			var counts []uint64
			for len(handler.records) != 0 {
				record := <-handler.records
				if record.Level != slog.LevelDebug || record.Message != "Dropping invalid, unknown-peer or full-queue WireGuard datagram." {
					t.Errorf("unexpected drop log: level=%v message=%q", record.Level, record.Message)
				}
				if record.NumAttrs() != 1 {
					t.Errorf("drop log attributes = %d, want 1", record.NumAttrs())
				}
				record.Attrs(func(attr slog.Attr) bool {
					if attr.Key != "dropped" || attr.Value.Kind() != slog.KindUint64 {
						t.Errorf("unexpected drop log field: %v", attr)
					}
					counts = append(counts, attr.Value.Uint64())
					return true
				})
			}
			wantCounts := slices.Clone(test.wantCounts)
			if count := test.wantDrops + 1; count&(count-1) == 0 {
				wantCounts = append(wantCounts, count)
			}
			// Concurrent logging can reorder records; compare the captured values.
			slices.Sort(wantCounts)
			slices.Sort(counts)
			if diff := gocmp.Diff(wantCounts, counts); diff != "" {
				t.Errorf("power-of-two drop counts (-want +got):\n%s", diff)
			}
			wantIndices := 1
			if test.register {
				wantIndices++
			}
			if len(demux.indices) != wantIndices {
				t.Error("dispatch changed locally registered indices")
			}
		})
	}
}
