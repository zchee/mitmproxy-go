// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"errors"
	"testing"
)

func TestReceiveStoppedPreservesConnectionError(t *testing.T) {
	client, server, ctx := newEndpointPair(t, ErrCodeGeneralProtocol)
	id, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields := []HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}}
	if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: fields, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-server.Done():
	case <-ctx.Done():
		t.Fatal("invalid request did not stop the endpoint:", ctx.Err())
	}
	// Occupy the notification lock so a stopped endpoint cannot select an
	// available lock instead of exercising its terminal-error branch.
	server.receiveLock <- struct{}{}
	defer func() { <-server.receiveLock }()
	_, err = server.Receive(ctx)
	failure, ok := errors.AsType[*ConnectionError](err)
	if !ok || failure.Code != ErrCodeGeneralProtocol {
		t.Fatalf("stopped receive = %v, want the original connection protocol error", err)
	}
}
