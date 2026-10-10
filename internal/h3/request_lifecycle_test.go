// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	quic "github.com/quic-go/quic-go"
)

func TestEndpointCancellationPreservesRequestFIN(t *testing.T) {
	// Completed writes certify FIN preservation; incomplete writes preserve reset behavior.
	tests := map[string]struct{ end bool }{
		"success: completed request retains FIN": {end: true},
		"success: incomplete request is reset":   {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, server, ctx := newEndpointPair(t)
			id, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fields := []HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}
			if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: fields}); err != nil {
				t.Fatal(err)
			}
			body := []byte("complete request body")
			if err := client.Send(ctx, Event{Kind: Data, Identity: id, Data: body, EndStream: test.end}); err != nil {
				t.Fatal(err)
			}
			head, err := server.Receive(ctx)
			if err != nil || head.Kind != Headers {
				t.Fatalf("request head = %+v, %v", head, err)
			}
			if diff := gocmp.Diff(fields, head.Headers); diff != "" {
				t.Fatal(diff)
			}
			if err := server.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []HeaderField{{Name: ":status", Value: "200"}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			if event, err := client.ReceiveStream(ctx, id); err != nil || event.Kind != Headers {
				t.Fatalf("response head = %+v, %v", event, err)
			}
			end, err := client.ReceiveStream(ctx, id)
			if err != nil || end.Kind != Data || !end.EndStream || end.Receipt == nil {
				t.Fatalf("response FIN = %+v, %v", end, err)
			}
			// Retain the response EOF receipt so StreamDone cannot retire the request.
			state, err := client.lookup(id)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-client.StreamDone(id):
				t.Fatal("request retired with an unsettled response receipt")
			default:
			}
			if err := client.CancelStream(id, ErrCodeRequestCancelled); err != nil {
				t.Fatal(err)
			}
			// Inspect the local write half even if QUIC already delivered its FIN.
			_, err = state.wire.Write(nil)
			reset, cancelled := errors.AsType[*quic.StreamError](err)
			if test.end && cancelled || !test.end && (!cancelled || reset.ErrorCode != quic.StreamErrorCode(ErrCodeRequestCancelled)) {
				t.Fatalf("write after cleanup = %v; completed request=%v", err, test.end)
			}
			if end.Receipt.Complete() {
				t.Fatal("cleanup did not invalidate the retained response receipt")
			}
			if test.end {
				var received []byte
				for {
					event, err := server.ReceiveStream(ctx, head.Identity)
					if err != nil || event.Kind != Data || event.Receipt == nil {
						t.Fatalf("completed request = %+v, %v", event, err)
					}
					received = append(received, event.Data...)
					if !event.Receipt.Complete() {
						t.Fatal("completed request receipt was invalidated")
					}
					if event.EndStream {
						break
					}
				}
				if diff := gocmp.Diff(body, received); diff != "" {
					t.Fatal(diff)
				}
			} else {
				select {
				case <-server.StreamFailed(head.Identity):
				case <-ctx.Done():
					t.Fatal("origin did not observe the incomplete request reset", ctx.Err())
				}
				event, err := server.ReceiveStream(ctx, head.Identity)
				if err != nil || event.Kind != Reset || event.Code != ErrCodeRequestCancelled {
					t.Fatalf("incomplete request = %+v, %v", event, err)
				}
			}
			other, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Send(ctx, Event{Kind: Headers, Identity: other, Headers: fields, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			sibling, err := server.Receive(ctx)
			if err != nil || sibling.Kind != Headers || sibling.Identity.Stream != other.Stream {
				t.Fatalf("sibling request = %+v, %v", sibling, err)
			}
			fin, err := server.ReceiveStream(ctx, sibling.Identity)
			if err != nil || fin.Kind != Data || !fin.EndStream || fin.Receipt == nil || !fin.Receipt.Complete() {
				t.Fatalf("sibling request FIN = %+v, %v", fin, err)
			}
			response := []HeaderField{{Name: ":status", Value: "204"}}
			if err := server.Send(ctx, Event{Kind: Headers, Identity: sibling.Identity, Headers: response, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			event, err := client.ReceiveStream(ctx, other)
			if err != nil || event.Kind != Headers {
				t.Fatalf("sibling response = %+v, %v", event, err)
			}
			if diff := gocmp.Diff(response, event.Headers); diff != "" {
				t.Fatal(diff)
			}
			fin, err = client.ReceiveStream(ctx, other)
			if err != nil || fin.Kind != Data || !fin.EndStream || fin.Receipt == nil || !fin.Receipt.Complete() {
				t.Fatalf("sibling response FIN = %+v, %v", fin, err)
			}
		})
	}
}
