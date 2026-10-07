// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestLocalControlQueueBound(t *testing.T) {
	tests := map[string]struct {
		count       int
		wantFailure bool
	}{
		"success: cancellation resets at the queue limit":   {count: MaxConcurrentStreams * 2},
		"error: cancellation resets exceed the queue limit": {count: MaxConcurrentStreams*2 + 1, wantFailure: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			e, err := New(conn, Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			o := newOwner(e, t.Context())
			o.peerSettings, o.controls = true, nil
			// A stalled active writer leaves all later reset controls queued.
			o.active = &writeFrame{kind: writePing}
			for i := range test.count {
				s := o.newStream(uint32(i*2 + 1))
				if s == nil {
					t.Fatal("stream reservation failed")
				}
				s.wireStarted = true
				o.cancel(s, http2.ErrCodeCancel, streamError(s.id, http2.ErrCodeCancel, "cancelled"), true)
				s.queue = nil
				o.settle()
			}
			failure, failed := errors.AsType[*ProtocolError](o.fatal)
			if failed != test.wantFailure || failed && failure.Code != http2.ErrCodeEnhanceYourCalm {
				t.Fatalf("cancellation control overflow = %v, want failure=%v", o.fatal, test.wantFailure)
			}
			if len(o.controls) != min(test.count, MaxConcurrentStreams*2) {
				t.Fatalf("queued controls = %d, want %d", len(o.controls), min(test.count, MaxConcurrentStreams*2))
			}
			if budget := e.Budget(); budget.Granted != 0 {
				t.Fatalf("cancelled streams retained reservation: %+v", budget)
			}
		})
	}
}

func TestFramerControlQueueBound(t *testing.T) {
	tests := map[string]struct {
		count       int
		framerError bool
		wantFailure bool
	}{
		"success: framer resets at the queue limit":     {count: MaxConcurrentStreams * 2, framerError: true},
		"error: framer resets exceed the queue limit":   {count: MaxConcurrentStreams*2 + 1, framerError: true, wantFailure: true},
		"success: normal controls at the queue limit":   {count: MaxConcurrentStreams * 2},
		"error: normal controls exceed the queue limit": {count: MaxConcurrentStreams*2 + 1, wantFailure: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var wire bytes.Buffer
			writer := http2.NewFramer(&wire, nil)
			for i := range test.count {
				var err error
				if test.framerError {
					id := uint32(i*2 + 1)
					err = writer.WriteRawFrame(http2.FrameWindowUpdate, 0, id, []byte{0, 0, 0, 0})
				} else {
					err = writer.WritePing(false, [8]byte{})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			endpoint, err := New(conn, Config{Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			owner := newOwner(endpoint, ctx)
			owner.peerSettings = true
			reads := make(chan readFrame)
			stopped := make(chan error, 1)
			go func() { stopped <- owner.run(reads, nil, nil) }()
			reader := http2.NewFramer(nil, &wire)
			for range test.count {
				frame, err := reader.ReadFrame()
				if test.framerError {
					if _, ok := errors.AsType[http2.StreamError](err); !ok {
						t.Fatalf("framer error = %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				incoming := readFrame{frame: frame, err: err, accepted: make(chan struct{})}
				select {
				case reads <- incoming:
				case <-ctx.Done():
					buf := make([]byte, 1<<20)
					t.Fatalf("owner stopped accepting bounded input:\n%s", buf[:runtime.Stack(buf, true)])
				}
			}
			cancel()
			<-stopped
			failure, failed := errors.AsType[*ProtocolError](owner.fatal)
			if diff := gocmp.Diff(test.wantFailure, failed); diff != "" {
				t.Fatal(diff)
			}
			if failed && failure.Code != http2.ErrCodeEnhanceYourCalm {
				t.Fatalf("queue overflow = %v", failure)
			}
			if len(owner.controls) > MaxConcurrentStreams*2+1 {
				t.Fatalf("control queue grew to %d", len(owner.controls))
			}
		})
	}
}
