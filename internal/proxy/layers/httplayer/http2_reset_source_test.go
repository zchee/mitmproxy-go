// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestHTTP2ResetSourceErrorBody(t *testing.T) {
	tests := map[string]struct {
		source  string
		code    http2.ErrCode
		message string
		debug   string
	}{
		"success: client reset label":                          {source: "client", code: http2.ErrCodeProtocol, message: "stream reset by client (PROTOCOL_ERROR)"},
		"error: server reset label":                            {source: "server", code: http2.ErrCodeProtocol, message: "stream reset by server (PROTOCOL_ERROR)"},
		"error: server connection close label":                 {source: "connection", code: http2.ErrCodeProtocol, message: "connection closed by server: origin failure", debug: "origin failure"},
		"error: opaque connection diagnostic remains internal": {source: "connection", code: http2.ErrCodeProtocol, message: "connection closed by server: <origin>&'\"\x00", debug: "<origin>&'\"\x00"},
		"error: large connection diagnostic remains internal":  {source: "connection", code: http2.ErrCodeProtocol, message: "connection closed by server: " + strings.Repeat("<", 64*1024), debug: strings.Repeat("<", 64*1024)},
		"success: numeric unknown reset code":                  {source: "server", code: 50, message: "stream reset by server (50)"},
		"success: local cancellation mapping":                  {source: "local", code: http2.ErrCodeCancel, message: "stream reset by client (CANCEL)"},
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
				err = server.Shutdown(t.Context(), test.code, []byte(test.debug))
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
			var protocolError ResponseProtocolError
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
				protocolError = event
				if test.source == "connection" {
					protocolError.Cause = fmt.Errorf("wrapped origin failure: %w", event.Cause)
				}
				if got, want := h2.IsConnectionClosed(protocolError.Cause), test.source == "connection"; got != want {
					t.Fatalf("typed connection classification = %v, want %v", got, want)
				}
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
			bodyMessage := test.message
			if test.source == "connection" {
				bodyMessage = "upstream closed the HTTP/2 connection"
			}
			wantBody := []byte("<html>\n<head>\n    <title>502 Bad Gateway</title>\n</head>\n<body>\n" +
				"    <h1>502 Bad Gateway</h1>\n    <p>" + bodyMessage + "</p>\n</body>\n</html>")
			// A genuine client reset or local cancellation keeps its existing status policy.
			if request || test.source == "local" {
				return
			}
			owner, manager := newTestStream(t, &streamAddon{})
			if err := manager.Do(t.Context(), func(context.Context) error {
				owner.flow = flow.NewHTTPFlow(owner.c.Data.Client, owner.c.Data.Server, true)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			out, err := owner.handle(t.Context(), protocolError)
			if err != nil || len(out.events) != 1 {
				t.Fatalf("stream error output = %+v, %v", out, err)
			}
			protocolError, ok := out.events[0].(ResponseProtocolError)
			if !ok {
				t.Fatalf("stream error output = %T", out.events[0])
			}
			if err := manager.Do(t.Context(), func(context.Context) error {
				if owner.flow.Error == nil || owner.flow.Error.Msg != test.message {
					t.Errorf("flow diagnostic = %+v, want %q", owner.flow.Error, test.message)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			h1Conn, h1Peer := layertest.Pipe(t)
			h1 := newHTTP1Server(h1Conn, newWireStore(), nil)
			if err := h1.Send(t.Context(), protocolError); err != nil {
				t.Fatal(err)
			}
			h1Response, err := http.ReadResponse(bufio.NewReader(h1Peer), &http.Request{Method: "GET"})
			if err != nil {
				t.Fatal(err)
			}
			h1Body, err := io.ReadAll(h1Response.Body)
			if closeErr := h1Response.Body.Close(); err != nil || closeErr != nil {
				t.Fatalf("HTTP/1 response body = %v, close = %v", err, closeErr)
			}
			if h1Response.StatusCode != 502 {
				t.Fatalf("HTTP/1 error status = %d, want 502", h1Response.StatusCode)
			}
			if diff := gocmp.Diff(wantBody, h1Body); diff != "" {
				t.Errorf("HTTP/1 wire 502 body (-want +got):\n%s", diff)
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
			if err := adapter.Send(t.Context(), protocolError); err != nil {
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
