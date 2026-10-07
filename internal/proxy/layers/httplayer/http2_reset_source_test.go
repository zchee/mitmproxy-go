// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/h2"
)

func TestHTTP2ResetSourceErrorBody(t *testing.T) {
	tests := map[string]struct {
		source  string
		code    http2.ErrCode
		message string
	}{
		"success: client reset label":          {source: "client", code: http2.ErrCodeProtocol, message: "stream reset by client (PROTOCOL_ERROR)"},
		"error: server reset label":            {source: "server", code: http2.ErrCodeProtocol, message: "stream reset by server (PROTOCOL_ERROR)"},
		"error: server connection close label": {source: "connection", code: http2.ErrCodeProtocol, message: "connection closed by server: origin failure"},
		"success: numeric unknown reset code":  {source: "server", code: 50, message: "stream reset by server (50)"},
		"success: local cancellation mapping":  {source: "local", code: http2.ErrCodeCancel, message: "stream reset by client (CANCEL)"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, server := h2EndpointPair(t)
			id, err := client.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			fields := []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}}
			if err := client.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: id, Headers: fields, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			head, err := server.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			stream := &http2Stream{engine: client, identity: id, id: 1}
			request := test.source == "client"
			switch test.source {
			case "client":
				stream.engine, stream.identity = server, head.Identity
				err = client.CancelStream(id, test.code)
			case "server":
				err = server.CancelStream(head.Identity, test.code)
			case "connection":
				err = server.Shutdown(t.Context(), test.code, []byte("origin failure"))
			case "local":
				err = client.CancelStream(id, test.code)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Peer cancellation queues a wire write; observe its processing before reading.
			await(t, stream.engine.StreamFailed(stream.identity))
			event, err := stream.receive(t.Context(), request, nil)
			if err != nil {
				t.Fatal(err)
			}
			var message string
			var code ErrorCode
			switch event := event.(type) {
			case RequestProtocolError:
				if !request {
					t.Fatalf("upstream reset became a request error: %+v", event)
				}
				message, code = event.Message, event.Code
			case ResponseProtocolError:
				if request {
					t.Fatalf("client reset became a response error: %+v", event)
				}
				message, code = event.Message, event.Code
			default:
				t.Fatalf("reset event = %#v", event)
			}
			wantCode := GenericServerError
			if request {
				wantCode = GenericClientError
			} else if test.source == "local" {
				wantCode = Cancel
			}
			if code != wantCode {
				t.Fatalf("reset classification = %v, want %v", code, wantCode)
			}
			if diff := gocmp.Diff(test.message, message); diff != "" {
				t.Fatalf("reset diagnostic (-want +got):\n%s", diff)
			}
			wantBody := formatError(502, test.message)
			if diff := gocmp.Diff(wantBody, formatError(502, message)); diff != "" {
				t.Fatalf("502 diagnostic body (-want +got):\n%s", diff)
			}
			// A genuine client reset or local cancellation keeps its existing status policy.
			if request || test.source == "local" {
				return
			}
			downstream, endpoint := h2EndpointPair(t)
			downID, err := downstream.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := downstream.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: downID, Headers: fields, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			head, err = endpoint.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			adapter := &http2Server{engine: endpoint, identity: head.Identity, id: 1}
			if err := adapter.Send(t.Context(), ResponseProtocolError{ID: 1, Message: message, Code: code}); err != nil {
				t.Fatal(err)
			}
			response, err := downstream.ReceiveStream(t.Context(), downID)
			if err != nil || response.Kind != h2.Headers || len(response.Headers) == 0 || response.Headers[0].Value != "502" {
				t.Fatalf("error response headers = %+v, %v", response, err)
			}
			var body bytes.Buffer
			for !response.EndStream {
				response, err = downstream.ReceiveStream(t.Context(), downID)
				if err != nil {
					t.Fatal(err)
				}
				body.Write(response.Data)
				if response.Receipt != nil {
					response.Receipt.Complete()
				}
			}
			if diff := gocmp.Diff(wantBody, body.Bytes()); diff != "" {
				t.Fatalf("wire 502 body (-want +got):\n%s", diff)
			}
		})
	}
}
