// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"testing"

	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"

	"github.com/zchee/mitmproxy-go/internal/h3"
)

func TestHTTP3DriverFailureAfterFIN(t *testing.T) {
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:test_receive_stop_sending.
	// Observe the peer's send-side reset after the request FIN has been consumed.
	tests := map[string]struct{ code h3.ErrorCode }{
		"cancel after request FIN":           {code: h3.ErrCodeRequestCancelled},
		"version fallback after request FIN": {code: h3.ErrCodeVersionFallback},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			stream, _ := newTestStream(t, &streamAddon{})
			peer, source := newHTTP3TestPeer(t, ctx, false)
			origin, destination := newHTTP3TestPeer(t, ctx, true)
			clientWire, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, clientWire, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}})
			if err := clientWire.Close(); err != nil {
				t.Fatal(err)
			}
			head, err := source.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			originID, err := destination.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			client := &http3Server{engine: source, identity: head.Identity, failureDone: source.StreamFailed(head.Identity), id: stream.id, head: &head}
			server := &http3Client{engine: destination, identity: originID, failureDone: destination.StreamFailed(originID), id: stream.id}
			done := make(chan error, 1)
			go func() { done <- (&streamDriver{stream: stream, client: client, server: server}).run(ctx) }()
			originWire, err := origin.conn.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, body, trailers := readHTTP3TestMessage(t, originWire)
			if len(body) != 0 || len(trailers) != 0 {
				t.Fatal("headers-only request acquired a body or trailers")
			}
			clientWire.CancelRead(quic.StreamErrorCode(test.code))
			select {
			case <-originWire.Context().Done():
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			failure, ok := errors.AsType[*quic.StreamError](context.Cause(originWire.Context()))
			if !ok || !failure.Remote || failure.ErrorCode != quic.StreamErrorCode(test.code) {
				t.Fatalf("origin send-side reset = %v, want remote %s", context.Cause(originWire.Context()), test.code)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
