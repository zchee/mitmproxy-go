// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"unicode/utf8"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func FuzzReadMessages(f *testing.F) {
	seeds := map[string]struct {
		wire                   []byte
		fromClient, compressed bool
	}{
		"RFC masked hello":     {[]byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}, true, false},
		"RFC compressed hello": {[]byte{0xc1, 7, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0}, false, true},
		"fragmented text":      {[]byte{0x01, 3, 'H', 'e', 'l', 0x80, 2, 'l', 'o'}, false, false},
		"interleaved ping":     {[]byte{0x01, 1, 'a', 0x89, 1, '!', 0x80, 1, 'b'}, false, false},
		"masked close":         {[]byte{0x88, 0x80, 0, 0, 0, 0}, true, false},
		"nonminimal length":    {[]byte{0x81, 126, 0, 1, 'a'}, false, false},
		"invalid UTF-8":        {[]byte{0x81, 2, 0xc0, 0xaf}, false, false},
		"oversized length":     {[]byte{0x82, 127, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false, false},
		"compressed empty":     {[]byte{0xc2, 1, 0}, false, true},
		"truncated mask":       {[]byte{0x82, 0x80, 1, 2}, true, false},
	}
	for _, seed := range seeds {
		f.Add(seed.wire, seed.fromClient, seed.compressed)
	}
	f.Fuzz(func(t *testing.T, wire []byte, fromClient, compressed bool) {
		if len(wire) > 64<<10 {
			return
		}
		original := bytes.Clone(wire)
		raw, peer := net.Pipe()
		if err := peer.Close(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		options := []gows.ConnOption{gows.WithBuffered(wire)}
		if compressed {
			options = append(options, gows.WithCompressionParams(gows.CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}))
		}
		conn := gows.NewClientConn(raw, options...)
		if fromClient {
			conn = gows.NewServerConn(raw, options...)
		}
		ctx, cancel := context.WithTimeout(t.Context(), layertest.Timeout)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { _ = conn.Abort() })
		defer stop()
		incoming := make(chan received)
		terminal := make(chan received, 2)
		done := make(chan struct{})
		stopCount := 0
		go func() {
			defer close(done)
			readMessages(ctx, conn, fromClient, incoming, terminal, func() { stopCount++ })
		}()
		t.Cleanup(func() { _ = conn.Abort(); cancel(); await(t, done) })
		var delivered, copies [][]byte
		for {
			select {
			case event := <-incoming:
				if event.fromClient != fromClient {
					t.Fatal("reader changed direction")
				}
				if event.op.IsControl() {
					if len(event.content) > 125 || event.op == gows.OpcodeClose {
						t.Fatalf("ordinary control event=%+v", event)
					}
				} else {
					if event.op != gows.OpcodeText && event.op != gows.OpcodeBinary {
						t.Fatalf("message opcode=%v", event.op)
					}
					if event.op == gows.OpcodeText && !utf8.Valid(event.content) {
						t.Fatal("reader emitted invalid complete text")
					}
					total := 0
					for _, length := range event.lengths {
						if length < 0 {
							t.Fatal("negative fragment length")
						}
						total += length
					}
					if total != len(event.content) || len(event.lengths) == 0 || len(event.lengths) > maxFragmentsPerMessage {
						t.Fatalf("invalid fragment accounting: total=%d content=%d fragments=%d", total, len(event.content), len(event.lengths))
					}
				}
				delivered = append(delivered, event.content)
				copies = append(copies, bytes.Clone(event.content))
			case event := <-terminal:
				if event.fromClient != fromClient {
					t.Fatal("terminal changed direction")
				}
				if event.op == gows.OpcodeClose {
					if _, err := gows.ParseClose(event.content); err != nil {
						t.Fatalf("unvalidated close: %v", err)
					}
				} else if event.err == nil {
					t.Fatal("terminal event has neither Close nor error")
				}
				await(t, done)
				wantStops := 1
				if _, protocol := errors.AsType[*gows.ProtocolError](event.err); protocol {
					wantStops = 0
				}
				if stopCount != wantStops {
					t.Fatalf("hook cancellations=%d, want %d", stopCount, wantStops)
				}
				for i, content := range delivered {
					if !bytes.Equal(content, copies[i]) {
						t.Fatal("a later frame overwrote a borrowed payload")
					}
				}
				if !bytes.Equal(wire, original) {
					t.Fatal("reader mutated caller-owned buffered bytes")
				}
				return
			case <-ctx.Done():
				t.Fatal("reader did not terminate on a finite prefix and EOF")
			}
		}
	})
}
