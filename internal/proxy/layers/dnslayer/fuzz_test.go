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
				boundary := len(data)
				if len(data) > 1 {
					selector := int(data[len(data)-2])<<8 | int(data[len(data)-1])
					boundary = 1 + selector%(len(data)-1)
				}
				_, err = peer.Write(data[:boundary])
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
