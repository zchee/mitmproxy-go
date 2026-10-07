// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestEndpointTrailers(t *testing.T) {
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
	if err := server.Send(ctx, Event{Kind: Data, Identity: head.Identity, Data: []byte("body")}); err != nil {
		t.Fatal(err)
	}
	fields := []HeaderField{{Name: "x-trailer", Value: "one"}, {Name: "x-trailer", Value: "two"}}
	if err := server.Send(ctx, Event{Kind: Trailers, Identity: head.Identity, Headers: fields, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []EventKind{Headers, Data, Trailers} {
		event, err := client.ReceiveStream(ctx, id)
		if err != nil || event.Kind != kind {
			t.Fatalf("event = %+v, %v; want %v", event, err, kind)
		}
		if kind == Data {
			if string(event.Data) != "body" || !event.Receipt.Complete() {
				t.Fatal("body DATA was not consumed")
			}
		}
		if kind == Trailers {
			if diff := gocmp.Diff(fields, event.Headers); diff != "" {
				t.Fatalf("trailers (-want +got):\n%s", diff)
			}
			if !event.EndStream {
				end, err := client.ReceiveStream(ctx, id)
				if err != nil || end.Kind != Data || !end.EndStream || len(end.Data) != 0 || end.Receipt == nil {
					t.Fatalf("trailers followed by FIN = %+v, %v", end, err)
				}
				end.Receipt.Complete()
			}
		}
	}
}

func TestEndpointBodylessResponse(t *testing.T) {
	tests := map[string]struct{ method, status string }{
		"HEAD metadata length":         {method: "HEAD", status: "200"},
		"not modified metadata length": {method: "GET", status: "304"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, server, ctx := newEndpointPair(t)
			id, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: []HeaderField{{Name: ":method", Value: test.method}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			head, err := server.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fields := []HeaderField{{Name: ":status", Value: test.status}, {Name: "content-length", Value: "5"}}
			if err := server.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: fields, EndStream: true}); err != nil {
				t.Fatalf("bodyless response rejected representation length: %v", err)
			}
			response, err := client.ReceiveStream(ctx, id)
			if err != nil || response.Kind != Headers {
				t.Fatalf("response head = %+v, %v", response, err)
			}
			if diff := gocmp.Diff(fields, response.Headers); diff != "" {
				t.Fatalf("metadata fields (-want +got):\n%s", diff)
			}
			for !response.EndStream {
				response, err = client.ReceiveStream(ctx, id)
				if err != nil || response.Kind != Data || len(response.Data) != 0 {
					t.Fatalf("bodyless response end = %+v, %v", response, err)
				}
				response.Receipt.Complete()
			}
		})
	}
}

func TestEndpointGoAwayBoundary(t *testing.T) {
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
	other, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	shutdown := make(chan error, 1)
	go func() { shutdown <- server.Shutdown(ctx, ErrCodeNoError, []byte("must not be on the wire")) }()
	away, err := client.Receive(ctx)
	if err != nil || away.Kind != GoAway || away.LastStreamID != other.Stream {
		t.Fatalf("GOAWAY = %+v, %v; want exclusive id %d", away, err, other.Stream)
	}
	if _, err := client.OpenStream(ctx); !errors.Is(err, ErrDraining) {
		t.Fatalf("admission after GOAWAY = %v", err)
	}
	reset, err := client.ReceiveStream(ctx, other)
	if err != nil || reset.Kind != Reset || reset.Code != ErrCodeRequestRejected {
		t.Fatalf("excluded request = %+v, %v", reset, err)
	}
	for !head.EndStream {
		head, err = server.ReceiveStream(ctx, head.Identity)
		if err != nil || head.Kind != Data {
			t.Fatalf("accepted request end = %+v, %v", head, err)
		}
		head.Receipt.Complete()
	}
	if err := server.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []HeaderField{{Name: ":status", Value: "204"}}, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	response, err := client.ReceiveStream(ctx, id)
	if err != nil || response.Kind != Headers {
		t.Fatalf("accepted response = %+v, %v", response, err)
	}
	for !response.EndStream {
		response, err = client.ReceiveStream(ctx, id)
		if err != nil || response.Kind != Data {
			t.Fatalf("accepted response end = %+v, %v", response, err)
		}
		response.Receipt.Complete()
	}
	select {
	case err := <-shutdown:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("drained shutdown did not finish", ctx.Err())
	}
}
