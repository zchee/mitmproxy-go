// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestInitialHeadersWriteOrder(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	e, err := New(conn, Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	o := newOwner(e, ctx)
	o.peerSettings, o.controls = true, nil
	first, second := o.newStream(1), o.newStream(3)
	o.nextLocal = 5
	firstSend := newRequest(ctx, send)
	firstSend.id, firstSend.event = first.id, Event{Kind: Headers, Identity: first.id, Headers: requestFields(), EndStream: true}
	o.request(firstSend)
	o.prepared = o.nextWrite()
	if o.prepared == nil || o.prepared.stream != first.id.Stream || first.wireStarted || o.lastLocal != 0 {
		t.Fatalf("prepared initial HEADERS = %+v, wireStarted = %v, lastLocal = %d", o.prepared, first.wireStarted, o.lastLocal)
	}

	reads := make(chan readFrame)
	writes := make(chan *writeFrame)
	written := make(chan writeResult, 1)
	stopped := make(chan struct{})
	e.started.Store(true)
	go func() {
		err := o.run(reads, writes, written)
		o.closeAll(err)
		close(e.done)
		close(stopped)
	}()
	t.Cleanup(func() { cancel(); <-stopped })
	secondSend := newRequest(ctx, send)
	secondSend.id, secondSend.event = second.id, Event{Kind: Headers, Identity: second.id, Headers: requestFields(), EndStream: true}
	select {
	case e.requests <- secondSend:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// An ordinary inbound frame invalidates the prepared HEADERS after the
	// cursor has advanced past stream 1 and both Send requests are pending.
	var wire bytes.Buffer
	if err := http2.NewFramer(&wire, nil).WritePing(true, [8]byte{}); err != nil {
		t.Fatal(err)
	}
	inbound, err := http2.NewFramer(nil, &wire).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})
	select {
	case reads <- readFrame{frame: inbound, accepted: accepted}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for _, r := range []*request{firstSend, secondSend} {
		frame := awaitCancelWrite(t, ctx, writes)
		if frame.kind != writeHeaders || frame.stream != r.id.Stream {
			t.Fatalf("initial wire HEADERS = kind %d stream %d, want HEADERS stream %d", frame.kind, frame.stream, r.id.Stream)
		}
		written <- writeResult{frame: frame}
		select {
		case result := <-r.result:
			if result.err != nil {
				t.Fatal(result.err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	cancel()
	<-stopped
	if !first.wireStarted || !second.wireStarted || o.lastLocal != second.id.Stream {
		t.Fatalf("dispatch state = first %v, second %v, lastLocal %d", first.wireStarted, second.wireStarted, o.lastLocal)
	}
}

func TestInitialHeadersGatePreservesWrites(t *testing.T) {
	tests := map[string]struct {
		client bool
		kind   EventKind
		cancel bool
	}{
		"success: cancelled unsent lower stream releases HEADERS": {client: true, kind: Headers, cancel: true},
		"success: started DATA bypasses unsent sibling":           {client: true, kind: Data},
		"success: started trailers bypass unsent sibling":         {client: true, kind: Trailers},
		"success: server responses may start out of order":        {kind: Headers},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			e, err := New(conn, Config{Client: test.client, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			o := newOwner(e, ctx)
			o.peerSettings, o.controls = true, nil
			first, second := o.newStream(1), o.newStream(3)
			o.nextLocal, o.cursor = 5, 1
			event := Event{Kind: test.kind, Identity: second.id, Headers: requestFields(), EndStream: true}
			if !test.client {
				event.Headers = []hpack.HeaderField{{Name: ":status", Value: "200"}}
			}
			if test.kind == Data || test.kind == Trailers {
				first.wireStarted, first.outHeaders, o.lastLocal = true, true, first.id.Stream
				event.Identity = first.id
				if test.kind == Data {
					event.Headers, event.Data = nil, []byte("body")
				} else {
					event.Headers = []hpack.HeaderField{{Name: "x-end", Value: "done"}}
				}
			}
			r := newRequest(ctx, send)
			r.id, r.event = event.Identity, event
			o.request(r)
			writes := make(chan *writeFrame)
			written := make(chan writeResult, 1)
			stopped := make(chan struct{})
			e.started.Store(true)
			go func() {
				err := o.run(nil, writes, written)
				o.closeAll(err)
				close(e.done)
				close(stopped)
			}()
			t.Cleanup(func() { cancel(); <-stopped })
			if test.cancel {
				if err := e.CancelStream(first.id, http2.ErrCodeCancel); err != nil {
					t.Fatal(err)
				}
			}
			// A positive writer handoff proves progress without a timing bound;
			// no idle-stream reset or connection error may precede this frame.
			frame := awaitCancelWrite(t, ctx, writes)
			wantKind := writeHeaders
			if test.kind == Data {
				wantKind = writeData
			}
			if frame.kind != wantKind || frame.stream != event.Identity.Stream {
				t.Fatalf("next write = %+v, want kind %d stream %d", frame, wantKind, event.Identity.Stream)
			}
			if test.kind == Data {
				if diff := gocmp.Diff(event.Data, frame.payload); diff != "" {
					t.Fatalf("DATA payload (-want +got):\n%s", diff)
				}
			}
			written <- writeResult{frame: frame}
			select {
			case result := <-r.result:
				if result.err != nil {
					t.Fatal(result.err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			cancel()
			<-stopped
			if test.cancel {
				failure, ok := errors.AsType[*StreamError](first.failed)
				if !ok || failure.Code != http2.ErrCodeCancel || first.wireStarted {
					t.Fatalf("unsent cancellation = %v, wireStarted = %v", first.failed, first.wireStarted)
				}
			}
		})
	}
}
