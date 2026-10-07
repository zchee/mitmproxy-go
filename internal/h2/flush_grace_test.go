// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestActiveWriteFlushGrace(t *testing.T) {
	tests := map[string]struct {
		complete bool
	}{
		"success: active write completes before flush grace": {complete: true},
		"error: active write stalls until flush grace":       {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clock := &testClock{now: time.Unix(0, 0)}
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			e, err := New(conn, Config{Client: true, Clock: clock, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			o := newOwner(e, ctx)
			o.peerSettings, o.controls = true, nil
			active := &writeFrame{kind: writePing}
			o.active = active
			r := newRequest(ctx, shutdown)
			r.code = http2.ErrCodeNo
			o.request(r)
			defer o.finishFlush()
			if o.abortError != nil || o.flushDeadline.IsZero() {
				t.Fatalf("active write aborted before grace started: abort=%v deadline=%v", o.abortError, o.flushDeadline)
			}
			clock.advance(GoAwayFlushGrace - time.Nanosecond)
			o.settle()
			if o.abortError != nil {
				t.Fatalf("active write aborted before grace elapsed: %v", o.abortError)
			}
			writes := make(chan *writeFrame)
			written := make(chan writeResult, 1)
			stopped := make(chan error, 1)
			go func() {
				err := o.run(nil, writes, written)
				o.closeAll(err)
				e.failure.Store(&result{err: err})
				close(e.done)
				stopped <- err
			}()
			t.Cleanup(func() { cancel(); <-e.Done() })
			_ = e.WaitSendCredit(ctx, layer.StreamIdentity{Endpoint: "endpoint"})
			select {
			case <-e.Done():
				t.Fatal("active writer stopped before the clock reached its deadline")
			default:
			}
			if test.complete {
				written <- writeResult{frame: active}
				frame := awaitCancelWrite(t, ctx, writes)
				if frame.kind != writeGoAway || frame.code != http2.ErrCodeNo {
					t.Fatalf("graceful flush write = %+v", frame)
				}
				written <- writeResult{frame: frame}
			} else {
				clock.advance(time.Nanosecond)
			}
			select {
			case err := <-stopped:
				if test.complete {
					if err != nil {
						t.Fatalf("completed active write failed flush: %v", err)
					}
				} else if failure, ok := errors.AsType[*ProtocolError](err); !ok || !failure.Timeout() {
					t.Fatalf("stalled flush result = %v, want typed deadline error", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			ack := <-r.result
			if test.complete && ack.err != nil || !test.complete && ack.err == nil {
				t.Fatalf("shutdown acknowledgement = %v, completed=%v", ack.err, test.complete)
			}
		})
	}
}
