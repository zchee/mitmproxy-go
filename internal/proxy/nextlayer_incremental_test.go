// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
)

func TestNextLayerLinearCopies(t *testing.T) {
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	body := make([]byte, 4092)
	copy(body, []byte{3, 3})
	copy(body[35:], []byte{0, 2, 0, 0x2f, 1, 0, 0x0f, 0xd1, 0, 21, 0x0f, 0xcd})
	wire := append([]byte{0x16, 3, 3, 0x10, 0, 1, 0, 0x0f, 0xfc}, body...)
	asked := make(chan struct{}, 1)
	var previous *byte
	var copied, calls, uncapped int
	c := newSelector(t, memoryConn{Conn: client, input: client}, func(_ context.Context, d *hookdata.NextLayer) error {
		calls++
		if previous != &d.DataClient[0] {
			copied += len(d.DataClient)
			previous = &d.DataClient[0]
		}
		if cap(d.DataClient) != len(d.DataClient) {
			uncapped++
		}
		if len(d.DataClient) == len(wire) {
			d.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		}
		asked <- struct{}{}
		return nil
	})
	done := startSelection(t, t.Context(), c)
	for i := range len(wire) {
		if _, err := peer.Write(wire[i : i+1]); err != nil {
			t.Fatal(err)
		}
		await(t, asked)
	}
	requireSelection(t, done)
	if calls != len(wire) || copied > 8*len(wire) || uncapped != 0 {
		t.Fatalf("one-byte sniffing: %d hook calls, %d bytes copied for %d input bytes, %d uncapped views; want one call per byte, linear copies and capped views", calls, copied, len(wire), uncapped)
	}
	t.Logf("one-byte sniffing: %d hook calls, %d bytes copied for %d input bytes", calls, copied, len(wire))
	_ = peer.Close()
	requireReplay(t, c.Client, wire)
}
