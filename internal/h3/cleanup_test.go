// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Child cancellation propagation may run asynchronously. Keep the peer's
// propagation callback pending so teardown ordering is observable without sleeps.
type pausedCancellationContext struct {
	context.Context
	release   <-chan struct{}
	callbacks sync.WaitGroup
}

// Value hides cancellation ancestry so context uses this AfterFunc scheduler.
func (*pausedCancellationContext) Value(any) any { return nil }

// AfterFunc schedules child cancellation and tracks it through test cleanup.
func (c *pausedCancellationContext) AfterFunc(f func()) func() bool {
	c.callbacks.Add(1)
	complete := sync.OnceFunc(c.callbacks.Done)
	stop := context.AfterFunc(c.Context, func() {
		defer complete()
		<-c.release
		f()
	})
	return func() bool {
		if stop() {
			complete()
			return true
		}
		return false
	}
}

func TestEndpointPairCleanupCancellation(t *testing.T) {
	tests := map[string]struct{ method, status string }{
		"HEAD metadata length":         {method: "HEAD", status: "200"},
		"not modified metadata length": {method: "GET", status: "304"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
			t.Cleanup(cancel)
			release := make(chan struct{})
			peerCtx := &pausedCancellationContext{Context: ctx, release: release}
			t.Cleanup(func() { close(release); peerCtx.callbacks.Wait() })
			client, server, ctx := newEndpointPairContexts(t, ctx, peerCtx, cancel, nil)
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
			if err := server.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []HeaderField{{Name: ":status", Value: test.status}, {Name: "content-length", Value: "5"}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			response, err := client.ReceiveStream(ctx, id)
			if err != nil || response.Kind != Headers {
				t.Fatalf("response = %+v, error = %v", response, err)
			}
			for !response.EndStream {
				response, err = client.ReceiveStream(ctx, id)
				if err != nil || response.Kind != Data || len(response.Data) != 0 {
					t.Fatalf("bodyless completion = %+v, error = %v", response, err)
				}
				response.Receipt.Complete()
			}
			// The fixture's cleanup must stop both borrowed connections before
			// a cancelled endpoint can reset critical streams on an active peer.
		})
	}
}
