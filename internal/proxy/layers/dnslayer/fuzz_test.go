// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"testing"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

// Upstream test_fuzz_unpack_tcp_message exercises length-prefixed input.
// Run this real-socket target with -fuzztime=200x -parallel=1 to avoid exhausting
// ephemeral ports through TIME_WAIT during an unbounded high-rate fuzz run.
func FuzzTCPMessages(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 12, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{255, 255, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > layer.MaxRecordBytes {
			return
		}
		peer, input := layertest.Pipe(t)
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
		go func() { _, err := peer.Write(data); _ = peer.CloseWrite(); written <- err }()
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
