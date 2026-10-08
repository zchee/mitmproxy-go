// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"io"
	"testing"

	"github.com/zchee/mitmproxy-go/flow"
)

func TestQUICWireSkippedStream(t *testing.T) {
	// py:test/mitmproxy/proxy/layers/quic/test__raw_layers.py:test_force_raw
	// maps the first observed client stream 6 to origin stream 2, not stream 6.
	tests := map[string]struct{ skipped int }{
		"one unused stream ID":       {skipped: 1},
		"multiple unused stream IDs": {skipped: 3},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 100)}
			s := newWireSession(t, nil, o)
			for range tt.skipped {
				if _, err := s.client.OpenUniStreamSync(s.ctx); err != nil {
					t.Fatal(err)
				}
			}
			stream, err := s.client.OpenUniStreamSync(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write([]byte("visible")); err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			peer, err := s.origin.AcceptUniStream(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(peer)
			if err != nil || string(data) != "VISIBLE" {
				t.Fatalf("first observed stream = %q, %v", data, err)
			}
			if peer.StreamID() != 2 {
				t.Fatalf("origin stream ID = %d, want 2", peer.StreamID())
			}
			f := wireAwait(t, o.ended)
			if id, _ := f.Metadata.Get("quic_stream_id_client"); id != int64(2+4*tt.skipped) {
				t.Fatalf("client metadata ID = %v", id)
			}
		})
	}
}
