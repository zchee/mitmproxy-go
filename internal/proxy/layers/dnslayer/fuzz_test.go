// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"testing"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

// Upstream test_fuzz_unpack_tcp_message exercises length-prefixed input.
// In-memory half-closes avoid filling kernel socket tables during long runs.
func FuzzTCPMessages(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 12, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{255, 255, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > layer.MaxRecordBytes {
			return
		}
		peer, input := layertest.MemoryPipe(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		o := &owner{ctx: ctx, events: make(chan messageEvent, 2)}
		recorder := proxy.Record(input)
		recorder.StopRecording()
		o.startReader(true, recorder, nil)
		defer func() {
			cancel()
			o.workers.Wait()
			for _, stop := range o.interrupts {
				stop()
			}
		}()
		written := make(chan error, 1)
		go func() {
			// Split the unchanged wire bytes once, including inside length fields,
			// without a synchronous goroutine hand-off for every input byte.
			var err error
			if len(data) != 0 {
				boundary := tcpSplitBoundary(data)
				if boundary != 0 {
					_, err = peer.Write(data[:boundary])
				}
				if err == nil && boundary < len(data) {
					_, err = peer.Write(data[boundary:])
				}
			}
			_ = peer.CloseWrite()
			written <- err
		}()
		for {
			event := await(t, o.events)
			if event.err != nil {
				break
			}
			_, _ = dns.Unpack(event.wire, nil)
		}
		_ = peer.Close()
		_ = await(t, written)
	})
}

func tcpSplitBoundary(data []byte) int {
	selector := fnv.New64a()
	_, _ = selector.Write(data)
	return int(selector.Sum64() % uint64(len(data)+1))
}

func TestTCPSplitBoundary(t *testing.T) {
	tests := map[string]struct {
		data []byte
		min  int
	}{
		"success: zero-count DNS header can split inside its body": {
			data: []byte{0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			min:  3,
		},
		"success: second frame can split beyond the first maximum frame": {
			data: make([]byte, layer.MaxRecordBytes),
			min:  65538,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if len(tt.data) == layer.MaxRecordBytes {
				binary.BigEndian.PutUint16(tt.data, 65535)
			}
			found := false
			boundaries := make(map[int]bool)
			// Vary only the transaction ID, preserving framing and zero counts.
			for id := range 1 << 16 {
				binary.BigEndian.PutUint16(tt.data[2:], uint16(id))
				boundary := tcpSplitBoundary(tt.data)
				if boundary < 0 || boundary > len(tt.data) {
					t.Fatalf("ID %d: boundary %d outside [0,%d]", id, boundary, len(tt.data))
				}
				boundaries[boundary] = true
				if boundary >= tt.min && boundary < len(tt.data) {
					found = true
				}
				if len(tt.data) > 14 && found {
					break
				}
			}
			if !found {
				t.Fatalf("no boundary in [%d,%d)", tt.min, len(tt.data))
			}
			if len(tt.data) == 14 && len(boundaries) != len(tt.data)+1 {
				t.Fatalf("selected %d of %d boundaries", len(boundaries), len(tt.data)+1)
			}
		})
	}
}

func TestTCPSplitBoundaryRange(t *testing.T) {
	tests := map[string]struct{ length int }{
		"success: empty":              {},
		"success: one byte":           {length: 1},
		"success: length prefix":      {length: 2},
		"success: framed DNS header":  {length: 14},
		"success: maximum DNS frame":  {length: 65537},
		"success: maximum fuzz input": {length: layer.MaxRecordBytes},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := make([]byte, tt.length)
			for value := range 256 {
				for i := range data {
					data[i] = byte(i + value)
				}
				if boundary := tcpSplitBoundary(data); boundary < 0 || boundary > len(data) {
					t.Fatalf("length %d, pattern %d: boundary %d out of range", len(data), value, boundary)
				}
			}
		})
	}
}

// Upstream test_fuzz_unpack_udp_message has no framing state; the owned codec
// validates the complete datagram before any hook-visible flow exists.
func FuzzUDPMessages(f *testing.F) {
	f.Add([]byte("Not a DNS packet"))
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			return
		}
		msg, err := dns.Unpack(data, nil)
		if err != nil && msg != nil {
			t.Fatal("malformed datagram returned a message")
		}
	})
}
