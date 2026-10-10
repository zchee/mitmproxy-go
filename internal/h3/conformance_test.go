// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"errors"
	"fmt"
	"runtime"
	"testing"

	quic "github.com/quic-go/quic-go"
)

func TestRolePseudoValidation(t *testing.T) {
	tests := map[string]struct {
		fields          []HeaderField
		response, valid bool
	}{
		"complete request":        {fields: []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}, valid: true},
		"request missing method":  {fields: []HeaderField{{Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}},
		"request missing scheme":  {fields: []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/"}}},
		"request missing path":    {fields: []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}}},
		"response status":         {fields: []HeaderField{{Name: ":status", Value: "200"}}, response: true, valid: true},
		"response missing status": {fields: []HeaderField{{Name: "x-field", Value: "value"}}, response: true},
		"request carries status":  {fields: []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":status", Value: "200"}}},
		"response carries method": {fields: []HeaderField{{Name: ":status", Value: "200"}, {Name: ":method", Value: "GET"}}, response: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validatePseudoFields(test.fields, test.response)
			if (err == nil) != test.valid {
				t.Fatalf("role validation = %v; response=%v valid=%v", err, test.response, test.valid)
			}
		})
	}
}

func TestRequiredRequestPseudoHeaders(t *testing.T) {
	client, server, ctx := newEndpointPair(t, ErrCodeGeneralProtocol)
	id, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields := []HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}}
	if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: fields, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	event, err := server.Receive(ctx)
	failure, ok := errors.AsType[*ConnectionError](err)
	if !ok || failure.Code != ErrCodeGeneralProtocol {
		t.Fatalf("missing scheme yielded %+v, %v; want connection protocol rejection", event, err)
	}
}

func TestStopSendingWithoutActiveSend(t *testing.T) {
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
	for !head.EndStream {
		head, err = server.ReceiveStream(ctx, head.Identity)
		if err != nil || head.Kind != Data {
			t.Fatalf("request end = %+v, %v", head, err)
		}
		head.Receipt.Complete()
	}
	local, err := client.lookup(id)
	if err != nil {
		t.Fatal(err)
	}
	failed := server.StreamFailed(head.Identity)
	// Only the read direction is cancelled: no RESET_STREAM accompanies it.
	local.wire.CancelRead(quic.StreamErrorCode(ErrCodeRequestCancelled))
	select {
	case <-failed:
	case <-ctx.Done():
		dump := make([]byte, 1<<20)
		n := runtime.Stack(dump, true)
		t.Fatalf("STOP_SENDING without writer was not observed: %v\n%s", ctx.Err(), dump[:n])
	}
	reset, err := server.ReceiveStream(ctx, head.Identity)
	if err != nil || reset.Kind != Reset || reset.Code != ErrCodeRequestCancelled {
		dump := make([]byte, 1<<20)
		n := runtime.Stack(dump, true)
		t.Fatalf("STOP_SENDING without writer yielded %+v, %v\n%s", reset, err, dump[:n])
	}
	select {
	case <-server.StreamFailed(head.Identity):
	case <-ctx.Done():
		t.Fatal("STOP_SENDING did not fail the exchange", ctx.Err())
	}
}

func TestTrailersFollowActualFIN(t *testing.T) {
	tests := map[string]struct{ lateData bool }{"delayed FIN": {}, "late DATA rejected": {lateData: true}}
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
			if err := server.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []HeaderField{{Name: ":status", Value: "200"}}}); err != nil {
				t.Fatal(err)
			}
			if event, err := client.ReceiveStream(ctx, id); err != nil || event.Kind != Headers {
				t.Fatalf("response head = %+v, %v", event, err)
			}
			state, err := server.lookup(head.Identity)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := encodeHeaders([]HeaderField{{Name: "x-trailer", Value: "one"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := writeFrame(state.wire, frameHeaders, payload); err != nil {
				t.Fatal(err)
			}
			trailer, err := client.ReceiveStream(ctx, id)
			if err != nil || trailer.Kind != Trailers || trailer.EndStream {
				t.Fatalf("trailers without FIN = %+v, %v; must not terminate the message", trailer, err)
			}
			if test.lateData {
				if err := writeFrame(state.wire, frameData, []byte("late")); err != nil {
					t.Fatal(err)
				}
			}
			// The late DATA rejection can cancel the write half before Close runs.
			if err := state.wire.Close(); err != nil && (!test.lateData || err.Error() != fmt.Sprintf("close called for canceled stream %d", state.wire.StreamID())) {
				t.Fatal(err)
			}
			end, err := client.ReceiveStream(ctx, id)
			if test.lateData {
				if err != nil || end.Kind != Reset || end.Code != ErrCodeFrameUnexpected {
					t.Fatalf("late frame after trailers = %+v, %v", end, err)
				}
			} else {
				if err != nil || end.Kind != Data || !end.EndStream || len(end.Data) != 0 || end.Receipt == nil {
					t.Fatalf("FIN message end = %+v, %v", end, err)
				}
				end.Receipt.Complete()
			}
		})
	}
}
