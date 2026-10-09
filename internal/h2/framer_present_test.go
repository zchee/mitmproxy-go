// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestMalformedPresentFramerError is a behavioural regression for a rejected
// frame on an existing stream. The parent reports a peer-reset diagnostic.
func TestMalformedPresentFramerError(t *testing.T) {
	tests := map[string]struct{ client bool }{
		"error: client frame on present request":  {},
		"error: server frame on present response": {client: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			peer := newPipePeer(t, Config{Client: test.client})
			peer.settings(t)
			var head Event
			if test.client {
				id, err := peer.endpoint.OpenStream(peer.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := peer.endpoint.Send(peer.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields()}); err != nil {
					t.Fatal(err)
				}
				peer.headers(t, 1, false, []hpack.HeaderField{{Name: ":status", Value: "200"}})
				head, err = peer.endpoint.ReceiveStream(peer.ctx, id)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				peer.headers(t, 1, false, requestFields())
				var err error
				head, err = peer.endpoint.Receive(peer.ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			// x/net/http2 frame.go rejects a zero increment as a stream error.
			if err := peer.framer.WriteRawFrame(http2.FrameWindowUpdate, 0, 1, []byte{0, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			reset, err := peer.endpoint.ReceiveStream(peer.ctx, head.Identity)
			if err != nil || reset.Kind != Reset || reset.Code != http2.ErrCodeProtocol {
				t.Fatalf("malformed stream event = %+v, %v", reset, err)
			}
			const want = "malformed HTTP/2 frame: stream error: stream ID 1; PROTOCOL_ERROR"
			if reset.Err == nil {
				t.Fatal("malformed frame has no diagnostic")
			}
			if diff := gocmp.Diff(want, reset.Err.Error()); diff != "" {
				t.Fatalf("malformed frame diagnostic (-want +got):\n%s", diff)
			}
			protocol, ok := errors.AsType[*ProtocolError](reset.Err)
			if !ok || protocol.Code != http2.ErrCodeProtocol || IsConnectionClosed(reset.Err) {
				t.Fatalf("malformed frame lost stream-only protocol cause: %v", reset.Err)
			}
			stream, ok := errors.AsType[*StreamError](reset.Err)
			if !ok || stream.Identity != head.Identity || stream.Code != http2.ErrCodeProtocol || !errors.Is(reset.Err, io.ErrClosedPipe) {
				t.Fatalf("malformed frame lost stream identity/closed cause: %v", reset.Err)
			}
			wire := peer.frame(t, func(frame wireFrame) bool { return frame.kind == http2.FrameRSTStream && frame.stream == 1 })
			if wire.code != http2.ErrCodeProtocol {
				t.Fatalf("wire reset code = %v, want PROTOCOL_ERROR", wire.code)
			}
			if test.client {
				id, err := peer.endpoint.OpenStream(peer.ctx)
				if err != nil {
					t.Fatalf("open sibling after malformed frame: %v", err)
				}
				if err := peer.endpoint.Send(peer.ctx, Event{Kind: Headers, Identity: id, Headers: requestFields(), EndStream: true}); err != nil {
					t.Fatal(err)
				}
				peer.headers(t, uint32(id.Stream), true, []hpack.HeaderField{{Name: ":status", Value: "200"}})
				response, err := peer.endpoint.ReceiveStream(peer.ctx, id)
				if err != nil || response.Kind != Headers || !response.EndStream {
					t.Fatalf("sibling response = %+v, %v", response, err)
				}
			} else {
				peer.headers(t, 3, true, requestFields())
				sibling, err := peer.endpoint.Receive(peer.ctx)
				if err != nil || sibling.Kind != Headers || sibling.Identity.Stream != 3 {
					t.Fatalf("sibling request = %+v, %v", sibling, err)
				}
				if err := peer.endpoint.Send(peer.ctx, Event{Kind: Headers, Identity: sibling.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "200"}}, EndStream: true}); err != nil {
					t.Fatal(err)
				}
				peer.frame(t, func(frame wireFrame) bool {
					return frame.kind == http2.FrameHeaders && frame.stream == 3 && frame.flags.Has(http2.FlagHeadersEndStream)
				})
			}
		})
	}
}

// TestMalformedConnectionFramerPreservation preserves connection-level DATA
// padding and header-continuation faults; neither is a present-stream rejection.
func TestMalformedConnectionFramerPreservation(t *testing.T) {
	tests := map[string]struct{ continuation bool }{
		"error: DATA padding remains a connection error":       {},
		"error: CONTINUATION order remains a connection error": {continuation: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			peer := newPipePeer(t, Config{})
			peer.settings(t)
			if test.continuation {
				if err := peer.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: false}); err != nil {
					t.Fatal(err)
				}
				if err := peer.framer.WriteContinuation(3, true, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				peer.headers(t, 1, false, requestFields())
				if _, err := peer.endpoint.Receive(peer.ctx); err != nil {
					t.Fatal(err)
				}
				if err := peer.framer.WriteRawFrame(http2.FrameData, http2.FlagDataPadded, 1, []byte{2}); err != nil {
					t.Fatal(err)
				}
			}
			wire := peer.frame(t, func(frame wireFrame) bool { return frame.kind == http2.FrameGoAway })
			if wire.code != http2.ErrCodeProtocol {
				t.Fatalf("connection fault GOAWAY = %v, want PROTOCOL_ERROR", wire.code)
			}
		})
	}
}
