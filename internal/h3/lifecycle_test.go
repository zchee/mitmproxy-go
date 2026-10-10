// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"bytes"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	quic "github.com/quic-go/quic-go"
	"go.uber.org/goleak"
)

func TestEndpointReceiveBoundAndSibling(t *testing.T) {
	ignored := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, ignored) })
	client, server, ctx := newEndpointPair(t)
	id, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields := []HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "localhost"}, {Name: ":path", Value: "/"}}
	if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: fields}); err != nil {
		t.Fatal(err)
	}
	head, err := server.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, err := server.lookup(head.Identity)
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		written <- client.Send(ctx, Event{Kind: Data, Identity: id, Data: bytes.Repeat([]byte("x"), ReceiveQueueBytes+ChunkSize), EndStream: true})
	}()
	for {
		state.mu.Lock()
		charged := state.bytes
		changed := state.changed
		state.mu.Unlock()
		if charged > ReceiveQueueBytes {
			t.Fatalf("charged %d > receive cap", charged)
		}
		if charged == ReceiveQueueBytes {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("queue never reached bounded reservation", ctx.Err())
		}
	}
	data, err := server.ReceiveStream(ctx, head.Identity)
	if err != nil || data.Kind != Data {
		t.Fatalf("borrowed DATA = %+v, %v", data, err)
	}
	state.mu.Lock()
	charged := state.bytes
	state.mu.Unlock()
	if charged != ReceiveQueueBytes {
		t.Fatalf("borrow released reservation: %d", charged)
	}
	other, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send(ctx, Event{Kind: Headers, Identity: other, Headers: fields, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	sibling, err := server.Receive(ctx)
	if err != nil || sibling.Identity.Stream != other.Stream {
		t.Fatalf("sibling blocked by saturated body: %+v, %v", sibling, err)
	}
	if err := server.CancelStream(head.Identity, ErrCodeRequestCancelled); err != nil {
		t.Fatal(err)
	}
	if data.Receipt.Complete() {
		t.Fatal("cancelled borrowed receipt accepted consumption")
	}
	state.mu.Lock()
	charged = state.bytes
	state.mu.Unlock()
	if charged != 0 {
		t.Fatalf("cancelled DATA reservation retained: %d", charged)
	}
	select {
	case err := <-written:
		if err != nil {
			failure, ok := errors.AsType[*StreamError](err)
			if !ok || failure.Code != ErrCodeRequestCancelled {
				t.Fatalf("cancelled Send = %v", err)
			}
		}
	case <-ctx.Done():
		t.Fatal("cancelled Send still holds borrowed data", ctx.Err())
	}
}

func TestEndpointPeerResetCode(t *testing.T) {
	client, server, ctx := newEndpointPair(t)
	id, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}}); err != nil {
		t.Fatal(err)
	}
	head, err := server.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	failed := client.StreamFailed(id)
	if err := server.CancelStream(head.Identity, ErrCodeVersionFallback); err != nil {
		t.Fatal(err)
	}
	reset, err := client.ReceiveStream(ctx, id)
	if err != nil || reset.Kind != Reset || reset.Code != ErrCodeVersionFallback {
		t.Fatalf("peer reset code = %+v, %v", reset, err)
	}
	select {
	case <-failed:
	case <-ctx.Done():
		t.Fatal("reset did not notify stream failure", ctx.Err())
	}
}

func TestEndpointCancellationPreservesResponseFIN(t *testing.T) {
	tests := map[string]struct{ end bool }{
		"success: completed response retains FIN": {end: true},
		"success: incomplete response is reset":   {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, server, ctx := newEndpointPair(t)
			id, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			head, err := server.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			end, err := server.ReceiveStream(ctx, head.Identity)
			if err != nil || !end.EndStream || end.Receipt == nil {
				t.Fatalf("request FIN = %+v, %v", end, err)
			}
			// Retain the EOF receipt so cleanup cannot rely on StreamDone yet.
			state, err := server.lookup(head.Identity)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []HeaderField{{Name: ":status", Value: "502"}}}); err != nil {
				t.Fatal(err)
			}
			body := []byte("502 Bad Gateway")
			if err := server.Send(ctx, Event{Kind: Data, Identity: head.Identity, Data: body, EndStream: test.end}); err != nil {
				t.Fatal(err)
			}
			if err := server.CancelStream(head.Identity, ErrCodeRequestCancelled); err != nil {
				t.Fatal(err)
			}
			// QUIC distinguishes a reset from a normally closed write half even
			// when the peer has already received its FIN.
			_, err = state.wire.Write(nil)
			reset, cancelled := errors.AsType[*quic.StreamError](err)
			if test.end && cancelled || !test.end && (!cancelled || reset.ErrorCode != quic.StreamErrorCode(ErrCodeRequestCancelled)) {
				t.Fatalf("write after cleanup = %v; completed response=%v", err, test.end)
			}
			if end.Receipt.Complete() {
				t.Fatal("cleanup did not invalidate the retained request receipt")
			}
			if !test.end {
				return
			}
			var received []byte
			for {
				event, err := client.ReceiveStream(ctx, id)
				if err != nil || event.Kind == Reset {
					t.Fatalf("completed response = %+v, %v", event, err)
				}
				if event.Kind == Headers {
					if diff := gocmp.Diff([]HeaderField{{Name: ":status", Value: "502"}}, event.Headers); diff != "" {
						t.Fatal(diff)
					}
				}
				received = append(received, event.Data...)
				if event.Receipt != nil {
					event.Receipt.Complete()
				}
				if event.EndStream {
					break
				}
			}
			if diff := gocmp.Diff(body, received); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestEndpointCriticalStreamErrors(t *testing.T) {
	tests := map[string]struct {
		code             ErrorCode
		closeControl     bool
		duplicateControl bool
		wire             []byte
	}{
		"critical closure":        {code: ErrCodeClosedCriticalStream, closeControl: true},
		"duplicate control":       {code: ErrCodeStreamCreation, duplicateControl: true},
		"reserved control frame":  {code: ErrCodeFrameUnexpected, wire: []byte{2, 0}},
		"duplicate settings":      {code: ErrCodeFrameUnexpected, wire: []byte{4, 0}},
		"reserved setting":        {code: ErrCodeSettingsError, wire: []byte{4, 2, 2, 0}},
		"request DATA on control": {code: ErrCodeFrameUnexpected, wire: []byte{0, 0}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, server, ctx := newEndpointPair(t, test.code)
			if _, err := client.OpenStream(ctx); err != nil {
				t.Fatal(err)
			}
			client.mu.Lock()
			control := client.control
			client.mu.Unlock()
			if control == nil {
				t.Fatal("control stream was not initialized")
			}
			if test.closeControl {
				if err := control.Close(); err != nil {
					t.Fatal(err)
				}
			} else if test.duplicateControl {
				stream, err := client.conn.openUniStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Write([]byte{0, 4, 0}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := control.Write(test.wire); err != nil {
				t.Fatal(err)
			}
			select {
			case <-server.Done():
			case <-ctx.Done():
				t.Fatal("protocol failure did not stop server", ctx.Err())
			}
			failure, ok := errors.AsType[*ConnectionError](server.endError())
			if !ok || failure.Code != test.code {
				t.Fatalf("connection failure = %v; want %v", server.endError(), test.code)
			}
		})
	}
}
