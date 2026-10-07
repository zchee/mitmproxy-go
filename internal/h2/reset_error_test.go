// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestResetErrorCausePreservation(t *testing.T) {
	tests := map[string]struct {
		kind string
	}{
		"success: stream error remains typed and closed": {kind: "stream"},
		"success: draining stream retains both causes":   {kind: "draining"},
		"success: connection error remains typed":        {kind: "connection"},
		"success: local context cancellation remains":    {kind: "context"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			e, err := New(conn, Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
			if err != nil {
				t.Fatal(err)
			}
			o := newOwner(e, t.Context())
			s := o.newStream(1)
			s.wireStarted = true
			var cause error
			var stream *StreamError
			var protocol *ProtocolError
			switch test.kind {
			case "stream", "draining":
				stream = &StreamError{Identity: s.id, Code: http2.ErrCodeCancel, Message: "stream failure"}
				cause = stream
				if test.kind == "draining" {
					cause = errors.Join(cause, ErrDraining)
				}
			case "connection":
				protocol = &ProtocolError{Code: http2.ErrCodeProtocol, Message: "HTTP/2 HEADERS deadline exceeded"}
				cause = protocol
			case "context":
				cause = context.Canceled
			}
			if test.kind == "connection" {
				o.fail(cause)
			} else {
				o.cancel(s, http2.ErrCodeCancel, cause, true)
			}
			reset := s.queue[0].event
			if !errors.Is(reset.Err, cause) {
				t.Fatalf("reset error lost its original cause: %v", reset.Err)
			}
			if stream != nil {
				var found *StreamError
				if !errors.As(reset.Err, &found) || found != stream {
					t.Fatalf("errors.As lost StreamError: %v", reset.Err)
				}
				if found, ok := errors.AsType[*StreamError](reset.Err); !ok || found != stream || !errors.Is(reset.Err, io.ErrClosedPipe) {
					t.Fatalf("reset lost typed closed-stream cause: %v", reset.Err)
				}
			}
			if protocol != nil {
				var found *ProtocolError
				if !errors.As(reset.Err, &found) || found != protocol {
					t.Fatalf("errors.As lost ProtocolError: %v", reset.Err)
				}
				if found, ok := errors.AsType[*ProtocolError](reset.Err); !ok || found != protocol || !found.Timeout() {
					t.Fatalf("reset lost typed timeout cause: %v", reset.Err)
				}
			}
			if test.kind == "draining" && !errors.Is(reset.Err, ErrDraining) {
				t.Fatalf("reset lost draining sentinel: %v", reset.Err)
			}
			if test.kind == "context" && !errors.Is(reset.Err, context.Canceled) {
				t.Fatalf("reset lost cancellation sentinel: %v", reset.Err)
			}
		})
	}
}
