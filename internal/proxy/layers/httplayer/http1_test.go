// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/internal/version"
)

// Ported from upstream test/mitmproxy/proxy/layers/http/test_http1.py at
// 3368a0a. Every upstream test function maps to a case below:
//
//	TestServer::test_simple         -> TestHTTP1ServerExchanges "success: simple ..."
//	TestServer::test_connect        -> TestHTTP1ServerExchanges "success: connect ..."
//	TestServer::test_upgrade        -> TestHTTP1ServerExchanges "success: upgrade ..."
//	TestServer::test_upgrade_denied -> TestHTTP1ServerExchanges "success: upgrade denied"
//	TestClient::test_simple         -> TestHTTP1ClientSimple
//	TestClient::test_connect        -> TestHTTP1ClientConnect
//	TestClient::test_upgrade        -> TestHTTP1ClientUpgrade
//	TestClient::test_upgrade_denied -> TestHTTP1ClientUpgradeDenied

// wireEvent is a comparable projection of one HTTP event.
type wireEvent struct {
	Kind     string
	ID       StreamID
	Method   string
	Status   int
	Data     string
	End      bool
	Code     ErrorCode
	Message  string
	Trailers string
}

func summarize(event Event) wireEvent {
	switch event := event.(type) {
	case RequestHeaders:
		return wireEvent{Kind: "request headers", ID: event.ID, Method: event.Request.Method, End: event.EndStream}
	case RequestData:
		return wireEvent{Kind: "request data", ID: event.ID, Data: string(event.Data)}
	case RequestTrailers:
		return wireEvent{Kind: "request trailers", ID: event.ID, Trailers: string(event.Trailers.Bytes())}
	case RequestEndOfMessage:
		return wireEvent{Kind: "request end", ID: event.ID}
	case RequestProtocolError:
		return wireEvent{Kind: "request error", ID: event.ID, Code: event.Code, Message: event.Message}
	case ResponseHeaders:
		return wireEvent{Kind: "response headers", ID: event.ID, Status: event.Response.StatusCode, End: event.EndStream}
	case ResponseData:
		return wireEvent{Kind: "response data", ID: event.ID, Data: string(event.Data)}
	case ResponseTrailers:
		return wireEvent{Kind: "response trailers", ID: event.ID, Trailers: string(event.Trailers.Bytes())}
	case ResponseEndOfMessage:
		return wireEvent{Kind: "response end", ID: event.ID}
	case ResponseProtocolError:
		return wireEvent{Kind: "response error", ID: event.ID, Code: event.Code, Message: event.Message}
	default:
		return wireEvent{Kind: fmt.Sprintf("unknown %T", event)}
	}
}

// requestPump drives ClientEndpoint.Receive on its own goroutine, as the
// stream driver's reader does, so wait states and kicks are exercised.
type requestPump struct {
	events chan RequestEvent
	errs   chan error
}

func pumpRequests(t *testing.T, endpoint ClientEndpoint) *requestPump {
	t.Helper()
	ctx := t.Context()
	pump := &requestPump{events: make(chan RequestEvent), errs: make(chan error, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			event, err := endpoint.Receive(ctx)
			if err != nil {
				pump.errs <- err
				return
			}
			select {
			case pump.events <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() { <-done })
	return pump
}

func (p *requestPump) next(t *testing.T) RequestEvent {
	t.Helper()
	select {
	case event := <-p.events:
		return event
	case err := <-p.errs:
		t.Fatalf("Receive() = error %v, want an event", err)
	case <-t.Context().Done():
		t.Fatal("test ended while waiting for an event")
	}
	return nil
}

func (p *requestPump) err(t *testing.T) error {
	t.Helper()
	select {
	case event := <-p.events:
		t.Fatalf("Receive() = %#v, want an error", summarize(event))
	case err := <-p.errs:
		return err
	case <-t.Context().Done():
		t.Fatal("test ended while waiting for an error")
	}
	return nil
}

func (p *requestPump) collect(t *testing.T, n int) []wireEvent {
	t.Helper()
	events := make([]wireEvent, 0, n)
	for range n {
		events = append(events, summarize(p.next(t)))
	}
	return events
}

func readExactly(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("reading %d bytes from the peer: %v (got %q)", n, err, buf)
	}
	return string(buf)
}

func readToEOF(t *testing.T, r io.Reader) string {
	t.Helper()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading to EOF: %v", err)
	}
	return string(data)
}

func writeAll(t *testing.T, w io.Writer, data string) {
	t.Helper()
	if _, err := io.WriteString(w, data); err != nil {
		t.Fatalf("writing %q to the peer: %v", data, err)
	}
}

func mustResponse(t *testing.T, status int, headers httpmsg.Headers) *httpmsg.Response {
	t.Helper()
	response, err := httpmsg.MakeResponse(status, nil, headers)
	if err != nil {
		t.Fatalf("MakeResponse(%d) = %v", status, err)
	}
	return response
}

func mustRequest(t *testing.T, method, url string, headers httpmsg.Headers) *httpmsg.Request {
	t.Helper()
	request, err := httpmsg.MakeRequest(method, url, nil, headers)
	if err != nil {
		t.Fatalf("MakeRequest(%s %s) = %v", method, url, err)
	}
	return request
}

const response200 = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"

func TestHTTP1ServerExchanges(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		first    string
		extra    string
		pipeline bool
		wantPre  []wireEvent
		status   int
		wantWire string
		wantPost []wireEvent
	}{
		"success: simple exchange": {
			first: "POST http://example.com/one HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
			extra: "GET http://example.com/two HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantPre: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "POST"},
				{Kind: "request data", ID: 1, Data: "abc"},
				{Kind: "request end", ID: 1},
			},
			status:   200,
			wantWire: response200,
			wantPost: []wireEvent{
				{Kind: "request headers", ID: 3, Method: "GET", End: true},
				{Kind: "request end", ID: 3},
			},
		},
		"success: simple exchange pipelined": {
			first:    "POST http://example.com/one HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
			extra:    "GET http://example.com/two HTTP/1.1\r\nHost: example.com\r\n\r\n",
			pipeline: true,
			wantPre: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "POST"},
				{Kind: "request data", ID: 1, Data: "abc"},
				{Kind: "request end", ID: 1},
			},
			status:   200,
			wantWire: response200,
			wantPost: []wireEvent{
				{Kind: "request headers", ID: 3, Method: "GET", End: true},
				{Kind: "request end", ID: 3},
			},
		},
		"success: connect tunnel": {
			first: "CONNECT example.com:443 HTTP/1.1\r\ncontent-length: 0\r\n\r\n",
			extra: "some plain tcp",
			wantPre: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "CONNECT", End: true},
			},
			status:   200,
			wantWire: response200,
			wantPost: []wireEvent{
				{Kind: "request data", ID: 1, Data: "some plain tcp"},
			},
		},
		"success: connect tunnel pipelined": {
			first:    "CONNECT example.com:443 HTTP/1.1\r\ncontent-length: 0\r\n\r\n",
			extra:    "some plain tcp",
			pipeline: true,
			wantPre: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "CONNECT", End: true},
			},
			status:   200,
			wantWire: response200,
			wantPost: []wireEvent{
				{Kind: "request data", ID: 1, Data: "some plain tcp"},
			},
		},
		"success: upgrade": {
			first: "POST http://example.com/one HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
			extra: "some websockets",
			wantPre: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "POST", End: true},
				{Kind: "request end", ID: 1},
			},
			status:   101,
			wantWire: "HTTP/1.1 101 Switching Protocols\r\ncontent-length: 0\r\n\r\n",
			wantPost: []wireEvent{
				{Kind: "request data", ID: 1, Data: "some websockets"},
			},
		},
		"success: upgrade pipelined": {
			first:    "POST http://example.com/one HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
			extra:    "some websockets",
			pipeline: true,
			wantPre: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "POST", End: true},
				{Kind: "request end", ID: 1},
			},
			status:   101,
			wantWire: "HTTP/1.1 101 Switching Protocols\r\ncontent-length: 0\r\n\r\n",
			wantPost: []wireEvent{
				{Kind: "request data", ID: 1, Data: "some websockets"},
			},
		},
		"success: upgrade denied": {
			first: "GET http://example.com/ HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
			extra: "GET / HTTP/1.1\r\n\r\n",
			wantPre: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "GET", End: true},
				{Kind: "request end", ID: 1},
			},
			status:   200,
			wantWire: response200,
			wantPost: []wireEvent{
				{Kind: "request headers", ID: 3, Method: "GET", End: true},
				{Kind: "request end", ID: 3},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, peer := layertest.Pipe(t)
			endpoint := newHTTP1Server(conn, newWireStore(), nil)
			pump := pumpRequests(t, endpoint)

			first := tt.first
			if tt.pipeline {
				first += tt.extra
			}
			writeAll(t, peer, first)
			if diff := gocmp.Diff(tt.wantPre, pump.collect(t, len(tt.wantPre))); diff != "" {
				t.Fatalf("events before the response differ (-want +got):\n%s", diff)
			}

			ctx := t.Context()
			if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: mustResponse(t, tt.status, nil)}); err != nil {
				t.Fatalf("Send(ResponseHeaders) = %v", err)
			}
			if err := endpoint.Send(ctx, ResponseEndOfMessage{ID: 1}); err != nil {
				t.Fatalf("Send(ResponseEndOfMessage) = %v", err)
			}
			if got := readExactly(t, peer, len(tt.wantWire)); got != tt.wantWire {
				t.Fatalf("response bytes = %q, want %q", got, tt.wantWire)
			}

			if !tt.pipeline {
				writeAll(t, peer, tt.extra)
			}
			if diff := gocmp.Diff(tt.wantPost, pump.collect(t, len(tt.wantPost))); diff != "" {
				t.Fatalf("events after the response differ (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHTTP1ServerHeadByByte(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)
	pump := pumpRequests(t, endpoint)

	for _, b := range []byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n") {
		writeAll(t, peer, string(b))
	}
	want := []wireEvent{
		{Kind: "request headers", ID: 1, Method: "GET", End: true},
		{Kind: "request end", ID: 1},
	}
	if diff := gocmp.Diff(want, pump.collect(t, len(want))); diff != "" {
		t.Fatalf("events differ (-want +got):\n%s", diff)
	}
}

func TestHTTP1ServerChunkedTrailers(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)
	pump := pumpRequests(t, endpoint)

	writeAll(t, peer, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: v\r\n\r\n")
	want := []wireEvent{
		{Kind: "request headers", ID: 1, Method: "POST"},
		{Kind: "request data", ID: 1, Data: "abc"},
		{Kind: "request trailers", ID: 1, Trailers: "X-Trailer: v\r\n"},
		{Kind: "request end", ID: 1},
	}
	if diff := gocmp.Diff(want, pump.collect(t, len(want))); diff != "" {
		t.Fatalf("events differ (-want +got):\n%s", diff)
	}

	ctx := t.Context()
	response := &httpmsg.Response{
		HTTPVersion: "HTTP/1.1", Headers: httpmsg.Headers{{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")}},
		StatusCode: 200,
		Reason:     "OK",
	}
	for _, event := range []ResponseEvent{
		ResponseHeaders{ID: 1, Response: response},
		ResponseData{ID: 1, Data: []byte("abc")},
		ResponseTrailers{ID: 1, Trailers: httpmsg.Headers{{Name: []byte("X-T"), Value: []byte("v")}}},
		ResponseEndOfMessage{ID: 1},
	} {
		if err := endpoint.Send(ctx, event); err != nil {
			t.Fatalf("Send(%T) = %v", event, err)
		}
	}
	wantWire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\n\r\n"
	if got := readExactly(t, peer, len(wantWire)); got != wantWire {
		t.Fatalf("response bytes = %q, want %q", got, wantWire)
	}
}

func TestHTTP1ServerHeadResponseOmitsTerminalChunk(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)
	pump := pumpRequests(t, endpoint)

	writeAll(t, peer, "HEAD / HTTP/1.1\r\n\r\n")
	pump.collect(t, 2)

	ctx := t.Context()
	response := &httpmsg.Response{
		HTTPVersion: "HTTP/1.1", Headers: httpmsg.Headers{{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")}},
		StatusCode: 200,
		Reason:     "OK",
	}
	if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: response}); err != nil {
		t.Fatalf("Send(ResponseHeaders) = %v", err)
	}
	if err := endpoint.Send(ctx, ResponseEndOfMessage{ID: 1}); err != nil {
		t.Fatalf("Send(ResponseEndOfMessage) = %v", err)
	}
	// A HEAD response carries no terminal chunk and no body, and the
	// connection stays usable: the next exchange parses normally.
	wantWire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	if got := readExactly(t, peer, len(wantWire)); got != wantWire {
		t.Fatalf("response bytes = %q, want %q", got, wantWire)
	}
	writeAll(t, peer, "GET / HTTP/1.1\r\n\r\n")
	want := []wireEvent{
		{Kind: "request headers", ID: 3, Method: "GET", End: true},
		{Kind: "request end", ID: 3},
	}
	if diff := gocmp.Diff(want, pump.collect(t, len(want))); diff != "" {
		t.Fatalf("events differ (-want +got):\n%s", diff)
	}
}

func TestHTTP1ServerConnectionClose(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		request         string
		responseHeaders httpmsg.Headers
		wantWire        string
	}{
		"success: request asks for close": {
			request:  "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
			wantWire: response200,
		},
		"success: http/1.0 closes": {
			request:  "GET / HTTP/1.0\r\n\r\n",
			wantWire: response200,
		},
		"success: response asks for close": {
			request:         "GET / HTTP/1.1\r\n\r\n",
			responseHeaders: httpmsg.Headers{{Name: []byte("Connection"), Value: []byte("close")}},
			wantWire:        "HTTP/1.1 200 OK\r\nConnection: close\r\ncontent-length: 0\r\n\r\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, peer := layertest.Pipe(t)
			endpoint := newHTTP1Server(conn, newWireStore(), nil)
			pump := pumpRequests(t, endpoint)

			writeAll(t, peer, tt.request)
			pump.collect(t, 2)

			ctx := t.Context()
			if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: mustResponse(t, 200, tt.responseHeaders)}); err != nil {
				t.Fatalf("Send(ResponseHeaders) = %v", err)
			}
			if err := endpoint.Send(ctx, ResponseEndOfMessage{ID: 1}); err != nil {
				t.Fatalf("Send(ResponseEndOfMessage) = %v", err)
			}
			if got := readToEOF(t, peer); got != tt.wantWire {
				t.Fatalf("response bytes = %q, want %q", got, tt.wantWire)
			}
			if err := pump.err(t); !errors.Is(err, io.EOF) {
				t.Fatalf("Receive() after close = %v, want io.EOF", err)
			}
		})
	}
}

func TestHTTP1ServerReceiveErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input      string
		close      bool
		wantEvents []wireEvent
		wantErr    string
	}{
		"error: malformed request line": {
			input: "invalid\r\n\r\n",
			wantEvents: []wireEvent{
				{Kind: "request error", ID: 1, Code: GenericClientError, Message: "Bad HTTP request line: b'invalid'"},
			},
		},
		"error: invalid framing still shows headers": {
			input: "GET http://example.com/ HTTP/1.1\r\nContent-Length: foo\r\n\r\n",
			wantEvents: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "GET"},
				{Kind: "request error", ID: 1, Code: GenericClientError, Message: `invalid content-length header: "foo"`},
			},
		},
		"error: oversized header line": {
			input: "GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", http1.MaxLineBytes) + "\r\n\r\n",
			wantEvents: []wireEvent{
				{
					Kind: "request error", ID: 1, Code: GenericClientError,
					Message: fmt.Sprintf("HTTP line exceeds byte limit: maximum %d", http1.MaxLineBytes),
				},
			},
		},
		"error: truncated head": {
			input:   "GET / HTTP/1.1\r\nHost: trunc",
			close:   true,
			wantErr: "client closed connection before completing request headers",
		},
		"error: truncated body": {
			input: "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab",
			close: true,
			wantEvents: []wireEvent{
				{Kind: "request headers", ID: 1, Method: "POST"},
				{Kind: "request data", ID: 1, Data: "ab"},
				{
					Kind: "request error", ID: 1, Code: GenericClientError,
					Message: "HTTP/1 protocol error: peer closed connection without sending complete message body (received 2 bytes, expected 5)",
				},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, peer := layertest.Pipe(t)
			endpoint := newHTTP1Server(conn, newWireStore(), nil)
			pump := pumpRequests(t, endpoint)

			writeAll(t, peer, tt.input)
			if tt.close {
				if err := peer.CloseWrite(); err != nil {
					t.Fatalf("CloseWrite() = %v", err)
				}
			}
			if len(tt.wantEvents) != 0 {
				if diff := gocmp.Diff(tt.wantEvents, pump.collect(t, len(tt.wantEvents))); diff != "" {
					t.Fatalf("events differ (-want +got):\n%s", diff)
				}
			}
			if tt.wantErr != "" {
				err := pump.err(t)
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Receive() = %v, want an error containing %q", err, tt.wantErr)
				}
			}
		})
	}
}

func TestHTTP1ServerClientDisconnectDuringResponseWait(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)
	pump := pumpRequests(t, endpoint)

	writeAll(t, peer, "GET http://example.com/ HTTP/1.1\r\n\r\n")
	pump.collect(t, 2)
	if err := peer.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() = %v", err)
	}
	want := []wireEvent{{Kind: "request error", ID: 1, Code: ClientDisconnected, Message: "Client disconnected."}}
	if diff := gocmp.Diff(want, pump.collect(t, 1)); diff != "" {
		t.Fatalf("events differ (-want +got):\n%s", diff)
	}
}

func TestHTTP1ServerErrorResponseBytes(t *testing.T) {
	t.Parallel()

	format := func(status int, reason, message string) string {
		body := fmt.Sprintf("<html>\n<head>\n    <title>%[1]d %[2]s</title>\n</head>\n<body>\n    <h1>%[1]d %[2]s</h1>\n    <p>%[3]s</p>\n</body>\n</html>", status, reason, message)
		return fmt.Sprintf("HTTP/1.1 %d %s\r\nServer: %s\r\nConnection: close\r\nContent-Type: text/html\r\ncontent-length: %d\r\n\r\n%s",
			status, reason, version.String(), len(body), body)
	}
	tests := map[string]struct {
		code     ErrorCode
		message  string
		wantWire string
	}{
		"success: unreachable origin yields 502": {
			code:     ConnectFailed,
			message:  "Server connection to example.com failed",
			wantWire: format(502, "Bad Gateway", "Server connection to example.com failed"),
		},
		"success: oversized request yields 413": {
			code:     RequestTooLarge,
			message:  "Request body exceeds mitmproxy's body_size_limit.",
			wantWire: format(413, "Payload Too Large", "Request body exceeds mitmproxy&#x27;s body_size_limit."),
		},
		"success: validation failure yields 400": {
			code:     RequestValidationFailed,
			message:  `Invalid request: <bad & "worse">`,
			wantWire: format(400, "Bad Request", "Invalid request: &lt;bad &amp; &quot;worse&quot;&gt;"),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, peer := layertest.Pipe(t)
			endpoint := newHTTP1Server(conn, newWireStore(), nil)
			pump := pumpRequests(t, endpoint)

			writeAll(t, peer, "GET http://example.com/ HTTP/1.1\r\n\r\n")
			pump.collect(t, 2)

			if err := endpoint.Send(t.Context(), ResponseProtocolError{ID: 1, Code: tt.code, Message: tt.message}); err != nil {
				t.Fatalf("Send(ResponseProtocolError) = %v", err)
			}
			if got := readToEOF(t, peer); got != tt.wantWire {
				t.Fatalf("error response bytes = %q, want %q", got, tt.wantWire)
			}
		})
	}
}

func TestHTTP1ServerDisconnectCodeSendsNoBody(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)
	pump := pumpRequests(t, endpoint)

	writeAll(t, peer, "GET http://example.com/ HTTP/1.1\r\n\r\n")
	pump.collect(t, 2)
	if err := endpoint.Send(t.Context(), ResponseProtocolError{ID: 1, Code: ClientDisconnected, Message: "peer closed connection"}); err != nil {
		t.Fatalf("Send(ResponseProtocolError) = %v", err)
	}
	if got := readToEOF(t, peer); got != "" {
		t.Fatalf("error response bytes = %q, want none", got)
	}
}

func TestHTTP1ServerTakeover(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)

	writeAll(t, peer, "CONNECT example.com:443 HTTP/1.1\r\n\r\n\r\nearly tunnel bytes")
	ctx := t.Context()
	event, err := endpoint.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() = %v", err)
	}
	want := wireEvent{Kind: "request headers", ID: 1, Method: "CONNECT", End: true}
	if diff := gocmp.Diff(want, summarize(event)); diff != "" {
		t.Fatalf("event differs (-want +got):\n%s", diff)
	}
	if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: mustResponse(t, 200, nil)}); err != nil {
		t.Fatalf("Send(ResponseHeaders) = %v", err)
	}
	if got := readExactly(t, peer, len(response200)); got != response200 {
		t.Fatalf("response bytes = %q, want %q", got, response200)
	}

	// The handover owns every byte after the request head, without the
	// superfluous newlines, and without accumulating tunnel data.
	got := string(endpoint.takeover())
	wantBytes := "early tunnel bytes"
	for len(got) < len(wantBytes) {
		buf := make([]byte, len(wantBytes)-len(got))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("reading the tunnel remainder: %v (got %q)", err, got)
		}
		got += string(buf[:n])
	}
	if got != wantBytes {
		t.Fatalf("takeover bytes = %q, want %q", got, wantBytes)
	}
}

func TestHTTP1ClientSimple(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		pipeline bool
	}{
		"success: sequential requests reuse the connection": {},
		"error: pipelining before the response is refused":  {pipeline: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, peer := layertest.Pipe(t)
			endpoint := newHTTP1Client(conn, newWireStore(), nil)
			ctx := t.Context()

			request := mustRequest(t, "GET", "http://example.com/", nil)
			if err := endpoint.Send(ctx, RequestHeaders{ID: 1, Request: request, EndStream: true}); err != nil {
				t.Fatalf("Send(RequestHeaders) = %v", err)
			}
			wantWire := "GET / HTTP/1.1\r\ncontent-length: 0\r\n\r\n"
			if got := readExactly(t, peer, len(wantWire)); got != wantWire {
				t.Fatalf("request bytes = %q, want %q", got, wantWire)
			}
			if err := endpoint.Send(ctx, RequestEndOfMessage{ID: 1}); err != nil {
				t.Fatalf("Send(RequestEndOfMessage) = %v", err)
			}

			if tt.pipeline {
				err := endpoint.Send(ctx, RequestHeaders{ID: 3, Request: request.Clone(), EndStream: true})
				if err == nil {
					t.Fatal("Send(RequestHeaders) during an exchange = nil, want an error")
				}
				return
			}

			writeAll(t, peer, response200)
			events := []wireEvent{
				{Kind: "response headers", ID: 1, Status: 200, End: true},
				{Kind: "response end", ID: 1},
			}
			for _, want := range events {
				event, err := endpoint.Receive(ctx)
				if err != nil {
					t.Fatalf("Receive() = %v", err)
				}
				if diff := gocmp.Diff(want, summarize(event)); diff != "" {
					t.Fatalf("event differs (-want +got):\n%s", diff)
				}
			}
			if err := endpoint.Send(ctx, RequestHeaders{ID: 3, Request: request.Clone(), EndStream: true}); err != nil {
				t.Fatalf("Send(RequestHeaders) for the next exchange = %v", err)
			}
			if got := readExactly(t, peer, len(wantWire)); got != wantWire {
				t.Fatalf("second request bytes = %q, want %q", got, wantWire)
			}
		})
	}
}

func TestHTTP1ClientConnect(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Client(conn, newWireStore(), nil)
	ctx := t.Context()

	request := mustRequest(t, "CONNECT", "http://example.com:443", nil)
	request.Authority = "example.com:443"
	if err := endpoint.Send(ctx, RequestHeaders{ID: 1, Request: request, EndStream: true}); err != nil {
		t.Fatalf("Send(RequestHeaders) = %v", err)
	}
	wantWire := "CONNECT example.com:443 HTTP/1.1\r\ncontent-length: 0\r\n\r\n"
	if got := readExactly(t, peer, len(wantWire)); got != wantWire {
		t.Fatalf("request bytes = %q, want %q", got, wantWire)
	}
	if err := endpoint.Send(ctx, RequestEndOfMessage{ID: 1}); err != nil {
		t.Fatalf("Send(RequestEndOfMessage) = %v", err)
	}

	writeAll(t, peer, "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\nsome plain tcp")
	// A successful CONNECT has no response end of message: the exchange
	// becomes a byte stream.
	events := []wireEvent{
		{Kind: "response headers", ID: 1, Status: 200, End: true},
		{Kind: "response data", ID: 1, Data: "some plain tcp"},
	}
	for _, want := range events {
		event, err := endpoint.Receive(ctx)
		if err != nil {
			t.Fatalf("Receive() = %v", err)
		}
		if diff := gocmp.Diff(want, summarize(event)); diff != "" {
			t.Fatalf("event differs (-want +got):\n%s", diff)
		}
	}
	if err := endpoint.Send(ctx, RequestData{ID: 1, Data: []byte("some more tcp")}); err != nil {
		t.Fatalf("Send(RequestData) = %v", err)
	}
	if got := readExactly(t, peer, len("some more tcp")); got != "some more tcp" {
		t.Fatalf("tunnel bytes = %q, want %q", got, "some more tcp")
	}
}

func TestHTTP1ClientUpgrade(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Client(conn, newWireStore(), nil)
	ctx := t.Context()

	request := mustRequest(t, "GET", "http://example.com/ws", httpmsg.Headers{
		{Name: []byte("Connection"), Value: []byte("Upgrade")},
		{Name: []byte("Upgrade"), Value: []byte("websocket")},
	})
	if err := endpoint.Send(ctx, RequestHeaders{ID: 1, Request: request, EndStream: true}); err != nil {
		t.Fatalf("Send(RequestHeaders) = %v", err)
	}
	wantWire := "GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\ncontent-length: 0\r\n\r\n"
	if got := readExactly(t, peer, len(wantWire)); got != wantWire {
		t.Fatalf("request bytes = %q, want %q", got, wantWire)
	}
	if err := endpoint.Send(ctx, RequestEndOfMessage{ID: 1}); err != nil {
		t.Fatalf("Send(RequestEndOfMessage) = %v", err)
	}

	writeAll(t, peer, "HTTP/1.1 101 Switching Protocols\r\ncontent-length: 0\r\n\r\nhello")
	events := []wireEvent{
		{Kind: "response headers", ID: 1, Status: 101, End: true},
		{Kind: "response end", ID: 1},
		{Kind: "response data", ID: 1, Data: "hello"},
	}
	for _, want := range events {
		event, err := endpoint.Receive(ctx)
		if err != nil {
			t.Fatalf("Receive() = %v", err)
		}
		if diff := gocmp.Diff(want, summarize(event)); diff != "" {
			t.Fatalf("event differs (-want +got):\n%s", diff)
		}
	}
	if err := endpoint.Send(ctx, RequestData{ID: 1, Data: []byte("some more websockets")}); err != nil {
		t.Fatalf("Send(RequestData) = %v", err)
	}
	if got := readExactly(t, peer, len("some more websockets")); got != "some more websockets" {
		t.Fatalf("upgraded bytes = %q, want %q", got, "some more websockets")
	}
}

func TestHTTP1ClientUpgradeDenied(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Client(conn, newWireStore(), nil)
	ctx := t.Context()

	request := mustRequest(t, "GET", "http://example.com/ws", httpmsg.Headers{
		{Name: []byte("Connection"), Value: []byte("Upgrade")},
		{Name: []byte("Upgrade"), Value: []byte("websocket")},
	})
	if err := endpoint.Send(ctx, RequestHeaders{ID: 1, Request: request, EndStream: true}); err != nil {
		t.Fatalf("Send(RequestHeaders) = %v", err)
	}
	wantWire := "GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\ncontent-length: 0\r\n\r\n"
	if got := readExactly(t, peer, len(wantWire)); got != wantWire {
		t.Fatalf("request bytes = %q, want %q", got, wantWire)
	}
	if err := endpoint.Send(ctx, RequestEndOfMessage{ID: 1}); err != nil {
		t.Fatalf("Send(RequestEndOfMessage) = %v", err)
	}

	writeAll(t, peer, "HTTP/1.1 200 Ok\r\ncontent-length: 0\r\n\r\n")
	events := []wireEvent{
		{Kind: "response headers", ID: 1, Status: 200, End: true},
		{Kind: "response end", ID: 1},
	}
	for _, want := range events {
		event, err := endpoint.Receive(ctx)
		if err != nil {
			t.Fatalf("Receive() = %v", err)
		}
		if diff := gocmp.Diff(want, summarize(event)); diff != "" {
			t.Fatalf("event differs (-want +got):\n%s", diff)
		}
	}
	if err := endpoint.Send(ctx, RequestHeaders{ID: 3, Request: request.Clone(), EndStream: true}); err != nil {
		t.Fatalf("Send(RequestHeaders) for the next exchange = %v", err)
	}
	if got := readExactly(t, peer, len(wantWire)); got != wantWire {
		t.Fatalf("second request bytes = %q, want %q", got, wantWire)
	}
}

func TestHTTP1ClientReadUntilClose(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Client(conn, newWireStore(), nil)
	ctx := t.Context()

	request := mustRequest(t, "GET", "http://example.com/", nil)
	if err := endpoint.Send(ctx, RequestHeaders{ID: 1, Request: request, EndStream: true}); err != nil {
		t.Fatalf("Send(RequestHeaders) = %v", err)
	}
	if err := endpoint.Send(ctx, RequestEndOfMessage{ID: 1}); err != nil {
		t.Fatalf("Send(RequestEndOfMessage) = %v", err)
	}
	writeAll(t, peer, "HTTP/1.1 200 OK\r\n\r\nhello")
	if err := peer.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() = %v", err)
	}
	events := []wireEvent{
		{Kind: "response headers", ID: 1, Status: 200},
		{Kind: "response data", ID: 1, Data: "hello"},
		{Kind: "response end", ID: 1},
	}
	for _, want := range events {
		event, err := endpoint.Receive(ctx)
		if err != nil {
			t.Fatalf("Receive() = %v", err)
		}
		if diff := gocmp.Diff(want, summarize(event)); diff != "" {
			t.Fatalf("event differs (-want +got):\n%s", diff)
		}
	}
	if _, err := endpoint.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("Receive() after until-close body = %v, want io.EOF", err)
	}
}

func TestHTTP1ClientReceiveErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		response  string
		close     bool
		wantEvent wireEvent
	}{
		"error: server closed connection": {
			close:     true,
			wantEvent: wireEvent{Kind: "response error", ID: 1, Code: GenericServerError, Message: "server closed connection"},
		},
		"error: partial response head": {
			response:  "HTTP/1.1 20",
			close:     true,
			wantEvent: wireEvent{Kind: "response error", ID: 1, Code: GenericServerError, Message: "unexpected server response"},
		},
		"error: malformed response line": {
			response:  "garbage\r\n\r\n",
			wantEvent: wireEvent{Kind: "response error", ID: 1, Code: GenericServerError, Message: "Cannot parse HTTP response: Bad HTTP response line: b'garbage'"},
		},
		"error: truncated chunked body": {
			response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
			close:    true,
			wantEvent: wireEvent{
				Kind: "response error", ID: 1, Code: GenericServerError,
				Message: "HTTP/1 protocol error: peer closed connection without sending complete message body (incomplete chunked read)",
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, peer := layertest.Pipe(t)
			endpoint := newHTTP1Client(conn, newWireStore(), nil)
			ctx := t.Context()

			request := mustRequest(t, "GET", "http://example.com/", nil)
			if err := endpoint.Send(ctx, RequestHeaders{ID: 1, Request: request, EndStream: true}); err != nil {
				t.Fatalf("Send(RequestHeaders) = %v", err)
			}
			if err := endpoint.Send(ctx, RequestEndOfMessage{ID: 1}); err != nil {
				t.Fatalf("Send(RequestEndOfMessage) = %v", err)
			}
			writeAll(t, peer, tt.response)
			if tt.close {
				if err := peer.CloseWrite(); err != nil {
					t.Fatalf("CloseWrite() = %v", err)
				}
			}
			for {
				event, err := endpoint.Receive(ctx)
				if err != nil {
					t.Fatalf("Receive() = %v, want event %#v", err, tt.wantEvent)
				}
				got := summarize(event)
				if got.Kind != tt.wantEvent.Kind {
					continue
				}
				if diff := gocmp.Diff(tt.wantEvent, got); diff != "" {
					t.Fatalf("event differs (-want +got):\n%s", diff)
				}
				break
			}
		})
	}
}

func TestHTTP1ClientUnexpectedServerData(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Client(conn, newWireStore(), nil)

	writeAll(t, peer, "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
	_, err := endpoint.Receive(t.Context())
	if err == nil || !strings.Contains(err.Error(), "unexpected data from server") {
		t.Fatalf("Receive() = %v, want an unexpected-data error", err)
	}
}

func TestHTTP1ClientProtocolErrorClosesConnection(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Client(conn, newWireStore(), nil)

	if err := endpoint.Send(t.Context(), RequestProtocolError{ID: 1, Code: Kill, Message: "killed"}); err != nil {
		t.Fatalf("Send(RequestProtocolError) = %v", err)
	}
	if got := readToEOF(t, peer); got != "" {
		t.Fatalf("bytes after protocol error = %q, want none", got)
	}
	_ = conn
}

func TestHTTP1Fidelity(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		raw       string
		mutate    func(*httpmsg.Request)
		wantWire  string
		wantCount uint64
	}{
		"success: unchanged head keeps its exact bytes": {
			raw:      "GET /x HTTP/1.1\r\nX-Foo: one\r\nx-BAR:\ttwo\r\nX-FOO: three\r\n\r\n",
			wantWire: "GET /x HTTP/1.1\r\nX-Foo: one\r\nx-BAR:\ttwo\r\nX-FOO: three\r\n\r\n",
		},
		"success: obs-fold joins and counts once": {
			raw:       "GET /x HTTP/1.1\r\nX-Long: a\r\n\tb\r\n\r\n",
			wantWire:  "GET /x HTTP/1.1\r\nX-Long: a\r\n b\r\n\r\n",
			wantCount: 1,
		},
		"success: handler change assembles canonically without counting": {
			raw: "GET /x HTTP/1.1\r\nX-Foo:  padded\r\nX-Keep: k\r\n\r\n",
			mutate: func(r *httpmsg.Request) {
				r.Headers.Set("X-Foo", "changed")
			},
			wantWire: "GET /x HTTP/1.1\r\nX-Foo: changed\r\nX-Keep: k\r\n\r\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			clientConn, clientPeer := layertest.Pipe(t)
			serverConn, serverPeer := layertest.Pipe(t)
			counter := &http1.FidelityCounter{}
			store := newWireStore()
			server := newHTTP1Server(clientConn, store, counter)
			client := newHTTP1Client(serverConn, store, counter)
			ctx := t.Context()

			writeAll(t, clientPeer, tt.raw)
			event, err := server.Receive(ctx)
			if err != nil {
				t.Fatalf("Receive() = %v", err)
			}
			headers, ok := event.(RequestHeaders)
			if !ok {
				t.Fatalf("Receive() = %#v, want request headers", summarize(event))
			}
			if tt.mutate != nil {
				tt.mutate(headers.Request)
			}
			if err := client.Send(ctx, headers); err != nil {
				t.Fatalf("Send(RequestHeaders) = %v", err)
			}
			if err := client.Send(ctx, RequestEndOfMessage{ID: 1}); err != nil {
				t.Fatalf("Send(RequestEndOfMessage) = %v", err)
			}
			if got := readExactly(t, serverPeer, len(tt.wantWire)); got != tt.wantWire {
				t.Fatalf("forwarded bytes = %q, want %q", got, tt.wantWire)
			}
			if got := counter.Load(); got != tt.wantCount {
				t.Fatalf("fidelity counter = %d, want %d", got, tt.wantCount)
			}
		})
	}
}

func TestHTTP1ServerWaitBufferBounded(t *testing.T) {
	t.Parallel()
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)
	pump := pumpRequests(t, endpoint)

	writeAll(t, peer, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	pump.collect(t, 1)

	// Flood the connection before the exchange completes; the endpoint must
	// bound what it buffers rather than grow without limit.
	go func() {
		chunk := strings.Repeat("a", 64<<10)
		for range (layer.MaxRecordBytes/len(chunk))*2 + 2 {
			if _, err := io.WriteString(peer, chunk); err != nil {
				return
			}
		}
	}()
	got := summarize(pump.next(t))
	if got.Kind != "request error" || got.Code != GenericClientError {
		t.Fatalf("event = %#v, want a request protocol error about the buffer bound", got)
	}
	if !strings.Contains(got.Message, "buffered more than") {
		t.Fatalf("message = %q, want the buffer bound", got.Message)
	}
}
