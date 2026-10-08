// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestEndpointUnannouncedResetDrain(t *testing.T) {
	tests := map[string]struct{ code ErrorCode }{
		"peer rejected request":  {code: ErrCodeRequestRejected},
		"peer cancelled request": {code: ErrCodeRequestCancelled},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
			t.Cleanup(cancel)
			client, server, ctx := newEndpointPairContexts(t, ctx, nil, cancel, nil)
			wire, err := client.conn.openStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			cancelRequestStream(wire, test.code)
			incoming, err := server.conn.acceptStream(ctx)
			if err != nil {
				t.Fatal("accept RESET-only stream:", err)
			}
			// Drive the request reader before starting its competing accept owner.
			server.ctx, server.cancel = context.WithCancel(ctx)
			state := newRequestState(server, incoming)
			server.streams[state.id.Stream] = state
			server.readRequest(state)
			state.mu.Lock()
			failure, resetDelivered := state.failure, state.resetDelivered
			state.mu.Unlock()
			server.cancel()
			if failure == nil || resetDelivered || len(server.notifications) != 0 {
				t.Fatalf("unannounced failure: failure=%v resetDelivered=%t notifications=%d", failure, resetDelivered, len(server.notifications))
			}
			if diff := gocmp.Diff(test.code, failure.Code); diff != "" {
				t.Fatalf("reset code (-want +got):\n%s", diff)
			}
			if len(server.streams) != 0 {
				t.Fatalf("unannounced reset still needs a nonexistent consumer: retained=%d", len(server.streams))
			}
			clientJoined, serverJoined := make(chan error, 1), make(chan error, 1)
			go func() { clientJoined <- client.Run(ctx) }()
			go func() { serverJoined <- server.Run(ctx) }()
			defer func() {
				cancel()
				<-clientJoined
				<-serverJoined
			}()
			if err := server.Shutdown(ctx, ErrCodeNoError, nil); err != nil {
				t.Fatal("drained shutdown:", err)
			}
		})
	}
}

func TestEndpointFailedStreamResetDelivery(t *testing.T) {
	tests := map[string]struct{ client bool }{
		"announced server request":       {},
		"client before response headers": {client: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, server, ctx := newEndpointPair(t)
			id, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := client
			if !test.client {
				if err := client.Send(ctx, Event{Kind: Headers, Identity: id, Headers: []HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}}); err != nil {
					t.Fatal(err)
				}
				head, err := server.Receive(ctx)
				if err != nil || head.Kind != Headers {
					t.Fatalf("request head = %+v, %v", head, err)
				}
				endpoint, id = server, head.Identity
			}
			if err := endpoint.CancelStream(id, ErrCodeRequestCancelled); err != nil {
				t.Fatal(err)
			}
			if _, err := endpoint.lookup(id); err != nil {
				t.Fatal("failed stream retired before reset delivery:", err)
			}
			reset, err := endpoint.ReceiveStream(ctx, id)
			if err != nil || reset.Kind != Reset {
				t.Fatalf("reset event = %+v, %v", reset, err)
			}
			if diff := gocmp.Diff(ErrCodeRequestCancelled, reset.Code); diff != "" {
				t.Fatalf("reset code (-want +got):\n%s", diff)
			}
			if _, err := endpoint.lookup(id); err == nil {
				t.Fatal("failed stream retained after reset delivery")
			}
		})
	}
}

func TestEndpointDrainBeforeGoAwayWrite(t *testing.T) {
	tests := map[string]struct{ status string }{
		"regular response":  {status: "200"},
		"bodyless response": {status: "204"},
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
			for !head.EndStream {
				head, err = server.ReceiveStream(ctx, head.Identity)
				if err != nil || head.Kind != Data {
					t.Fatalf("request end = %+v, %v", head, err)
				}
				head.Receipt.Complete()
			}
			server.controlLock <- struct{}{}
			held := true
			defer func() {
				if held {
					<-server.controlLock
				}
			}()
			shutdown := make(chan error, 1)
			go func() { shutdown <- server.Shutdown(ctx, ErrCodeNoError, nil) }()
			for {
				server.mu.Lock()
				draining, changed := server.draining, server.changed
				server.mu.Unlock()
				if draining {
					break
				}
				select {
				case <-changed:
				case <-ctx.Done():
					t.Fatal("admission remained open while GOAWAY waited for its writer:", ctx.Err())
				}
			}
			if err := server.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []HeaderField{{Name: ":status", Value: test.status}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-server.StreamDone(head.Identity):
			case <-ctx.Done():
				t.Fatal("accepted stream did not retire:", ctx.Err())
			}
			if server.ctx.Err() != nil {
				t.Fatal("drain stopped the control stream before GOAWAY was written:", server.ctx.Err())
			}
			<-server.controlLock
			held = false
			away, err := client.Receive(ctx)
			if err != nil || away.Kind != GoAway {
				t.Fatalf("GOAWAY = %+v, %v", away, err)
			}
			if diff := gocmp.Diff(id.Stream+4, away.LastStreamID); diff != "" {
				t.Fatalf("exclusive rejection boundary (-want +got):\n%s", diff)
			}
			if err := <-shutdown; err != nil {
				t.Fatal("drained shutdown:", err)
			}
		})
	}
}
