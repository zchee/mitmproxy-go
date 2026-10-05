// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// fakeClient feeds request events to the driver and records what it is sent.
type fakeClient struct {
	events chan RequestEvent

	mu   sync.Mutex
	sent []ResponseEvent
	seen chan ResponseEvent
}

func newFakeClient() *fakeClient {
	return &fakeClient{events: make(chan RequestEvent, 16), seen: make(chan ResponseEvent, 16)}
}

func (c *fakeClient) Receive(ctx context.Context) (RequestEvent, error) {
	select {
	case event, ok := <-c.events:
		if !ok {
			return nil, io.EOF
		}
		return event, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeClient) Send(ctx context.Context, event ResponseEvent) error {
	event = cloneEvent(event).(ResponseEvent)
	c.mu.Lock()
	c.sent = append(c.sent, event)
	c.mu.Unlock()
	select {
	case c.seen <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *fakeClient) responses() []ResponseEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.sent)
}

// fakeServer answers request events with scripted responses. Send blocks
// while blocked is non-nil and not yet closed, simulating an origin that
// stopped reading; it honors cancellation as the endpoint contract requires.
type fakeServer struct {
	events chan ResponseEvent

	mu      sync.Mutex
	sent    []RequestEvent
	started chan RequestEvent
	blocked chan struct{}
	wire    net.Conn
}

func newFakeServer() *fakeServer {
	return &fakeServer{events: make(chan ResponseEvent, 16), started: make(chan RequestEvent, 16)}
}

func (s *fakeServer) Receive(ctx context.Context) (ResponseEvent, error) {
	select {
	case event, ok := <-s.events:
		if !ok {
			return nil, io.EOF
		}
		return event, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *fakeServer) Send(ctx context.Context, event RequestEvent) error {
	event = cloneEvent(event).(RequestEvent)
	s.mu.Lock()
	gate := s.blocked
	s.mu.Unlock()
	select {
	case s.started <- event:
	case <-ctx.Done():
		return ctx.Err()
	}
	if _, data := event.(RequestData); gate != nil && data {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if data, ok := event.(RequestData); ok && s.wire != nil {
		stopped := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			_ = s.wire.Close()
			close(stopped)
		})
		defer func() {
			if !stop() {
				<-stopped
			}
		}()
		if _, err := s.wire.Write(data.Data); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.sent = append(s.sent, event)
	s.mu.Unlock()
	return nil
}

func (s *fakeServer) stopReading() {
	s.mu.Lock()
	s.blocked = make(chan struct{})
	s.mu.Unlock()
}

func (s *fakeServer) requests() []RequestEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.sent)
}

func cloneEvent(event Event) Event {
	switch event := event.(type) {
	case RequestHeaders:
		event.Request = event.Request.Clone()
		return event
	case ResponseHeaders:
		event.Response = event.Response.Clone()
		return event
	case RequestData:
		event.Data = bytes.Clone(event.Data)
		return event
	case ResponseData:
		event.Data = bytes.Clone(event.Data)
		return event
	case RequestTrailers:
		event.Trailers = event.Trailers.Clone()
		return event
	case ResponseTrailers:
		event.Trailers = event.Trailers.Clone()
		return event
	default:
		return event
	}
}

func eventTypes(events []Event) []string {
	types := make([]string, 0, len(events))
	for _, event := range events {
		switch event.(type) {
		case RequestHeaders:
			types = append(types, "requestheaders")
		case RequestData:
			types = append(types, "requestdata")
		case RequestTrailers:
			types = append(types, "requesttrailers")
		case RequestEndOfMessage:
			types = append(types, "requestend")
		case RequestProtocolError:
			types = append(types, "requesterror")
		case ResponseHeaders:
			types = append(types, "responseheaders")
		case ResponseData:
			types = append(types, "responsedata")
		case ResponseTrailers:
			types = append(types, "responsetrailers")
		case ResponseEndOfMessage:
			types = append(types, "responseend")
		case ResponseProtocolError:
			types = append(types, "responseerror")
		}
	}
	return types
}

func requestEventsAsEvents(events []RequestEvent) []Event {
	out := make([]Event, len(events))
	for i, event := range events {
		out[i] = event
	}
	return out
}

func responseEventsAsEvents(events []ResponseEvent) []Event {
	out := make([]Event, len(events))
	for i, event := range events {
		out[i] = event
	}
	return out
}

func TestDriverRoundTrip(t *testing.T) {
	a := &streamAddon{}
	s, _ := newTestStream(t, a)
	client, server := newFakeClient(), newFakeServer()
	client.events <- requestHead("3")
	client.events <- RequestData{ID: 1, Data: []byte("abc")}
	client.events <- RequestEndOfMessage{ID: 1}
	go func() {
		for event := range server.started {
			if _, ok := event.(RequestEndOfMessage); ok {
				server.events <- responseHead("3")
				server.events <- ResponseData{ID: 1, Data: []byte("def")}
				server.events <- ResponseEndOfMessage{ID: 1}
			}
		}
	}()
	d := &streamDriver{stream: s, client: client, server: server}
	if err := d.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(server.started)
	want := []string{"requestheaders", "requestdata", "requestend"}
	if diff := gocmp.Diff(want, eventTypes(requestEventsAsEvents(server.requests()))); diff != "" {
		t.Fatal(diff)
	}
	want = []string{"responseheaders", "responsedata", "responseend"}
	if diff := gocmp.Diff(want, eventTypes(responseEventsAsEvents(client.responses()))); diff != "" {
		t.Fatal(diff)
	}
	if diff := gocmp.Diff([]string{"requestheaders", "request", "responseheaders", "response"}, a.calls); diff != "" {
		t.Fatal(diff)
	}
}

func TestDriverEarlyResponseWhileUploadBlocked(t *testing.T) {
	a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		if name == "requestheaders" {
			f.Request.Stream = true
		}
	}}
	s, _ := newTestStream(t, a)
	client, server := newFakeClient(), newFakeServer()
	var origin net.Conn
	server.wire, origin = net.Pipe()
	t.Cleanup(func() { _ = server.wire.Close(); _ = origin.Close() })
	d := &streamDriver{stream: s, client: client, server: server}
	done := make(chan error, 1)
	go func() { done <- d.run(t.Context()) }()

	head := requestHead("6")
	client.events <- head
	if got := <-server.started; got.(RequestHeaders).Request == nil {
		t.Fatal("missing streamed request head")
	}
	// The real pipe peer never reads: the first upload chunk blocks in
	// net.Conn.Write. Response events must still reach the client.
	client.events <- RequestData{ID: 1, Data: []byte("abc")}
	<-server.started
	client.events <- RequestData{ID: 1, Data: []byte("def")}

	response := &httpmsg.Response{
		HTTPVersion: "HTTP/1.1", StatusCode: 413, Reason: "Request Entity Too Large",
		Headers: httpmsg.Headers{{Name: []byte("Content-Length"), Value: []byte("0")}},
	}
	server.events <- ResponseHeaders{ID: 1, Response: response, EndStream: true}
	server.events <- ResponseEndOfMessage{ID: 1}
	for {
		event := <-client.seen
		if _, ok := event.(ResponseEndOfMessage); ok {
			break
		}
		if head, ok := event.(ResponseHeaders); ok && head.Response.StatusCode != 413 {
			t.Fatalf("response head = %d", head.Response.StatusCode)
		}
	}
	if diff := gocmp.Diff([]string{"requestheaders", "responseheaders", "response"}, a.calls); diff != "" {
		t.Fatalf("response delivery waited for the blocked upload: %s", diff)
	}

	// The origin then closes without reading the rest of the upload. The
	// driver cancels the blocked upload write instead of deadlocking.
	close(server.events)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	close(server.started)
	for _, event := range server.requests() {
		if _, data := event.(RequestData); data {
			t.Fatalf("cancelled upload still delivered a body chunk: %v", event)
		}
	}
	if !s.failed {
		t.Fatal("origin close did not terminate the stream")
	}
}

func TestDriverWaitsForFinalTransformDelivery(t *testing.T) {
	a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		if name == "requestheaders" {
			f.Request.StreamFunc = func(b []byte) [][]byte {
				if len(b) == 0 {
					return [][]byte{[]byte("end")}
				}
				return [][]byte{b}
			}
		}
	}}
	s, m := newTestStream(t, a)
	client, server := newFakeClient(), newFakeServer()
	server.stopReading()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (&streamDriver{stream: s, client: client, server: server}).run(ctx) }()
	client.events <- requestHead("3")
	client.events <- RequestEndOfMessage{ID: 1}
	<-server.started
	<-server.started
	server.events <- responseHead("0")
	server.events <- ResponseEndOfMessage{ID: 1}
	for event := range client.seen {
		if _, ok := event.(ResponseEndOfMessage); ok {
			break
		}
	}
	if err := m.Do(t.Context(), func(context.Context) error {
		if diff := gocmp.Diff([]string{"requestheaders", "responseheaders", "response"}, a.calls); diff != "" {
			t.Errorf("hook before final bytes were delivered: %s", diff)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	close(server.blocked)
	server.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDriverCancellation(t *testing.T) {
	tests := map[string]struct{ blocked bool }{
		"success: cancel idle receivers": {},
		"success: cancel blocked upload": {true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" {
					f.Request.Stream = true
				}
			}}
			s, _ := newTestStream(t, a)
			client, server := newFakeClient(), newFakeServer()
			server.stopReading()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- (&streamDriver{stream: s, client: client, server: server}).run(ctx) }()
			if tt.blocked {
				client.events <- requestHead("3")
				client.events <- RequestData{ID: 1, Data: []byte("abc")}
				<-server.started
				<-server.started
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation returned %v, want context.Canceled", err)
			}
		})
	}
}

func TestDriverImmediateCloseAfterEarlyResponse(t *testing.T) {
	a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		if name == "requestheaders" {
			f.Request.Stream = true
		}
	}}
	s, _ := newTestStream(t, a)
	client, server := newFakeClient(), newFakeServer()
	server.stopReading()
	done := make(chan error, 1)
	go func() { done <- (&streamDriver{stream: s, client: client, server: server}).run(t.Context()) }()
	client.events <- requestHead("3")
	client.events <- RequestData{ID: 1, Data: []byte("abc")}
	<-server.started
	<-server.started
	head := responseHead("0")
	head.Response.StatusCode = 413
	server.events <- head
	server.events <- ResponseEndOfMessage{ID: 1}
	close(server.events)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"responseheaders", "responseend", "responseerror"}, eventTypes(responseEventsAsEvents(client.responses()))); diff != "" {
		t.Fatalf("origin close lost its completed response: %s", diff)
	}
	if diff := gocmp.Diff([]string{"requestheaders", "responseheaders", "response"}, a.calls); diff != "" {
		t.Fatal(diff)
	}
}

func TestDriverPreservesNextRequest(t *testing.T) {
	a := &streamAddon{}
	s, _ := newTestStream(t, a)
	client, server := newFakeClient(), newFakeServer()
	client.events <- requestHead("0")
	client.events <- RequestEndOfMessage{ID: 1}
	next := requestHead("0")
	next.ID = 3
	client.events <- next
	done := make(chan error, 1)
	go func() { done <- (&streamDriver{stream: s, client: client, server: server}).run(t.Context()) }()
	for event := range server.started {
		if _, end := event.(RequestEndOfMessage); end {
			break
		}
	}
	server.events <- responseHead("0")
	server.events <- ResponseEndOfMessage{ID: 1}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-client.events:
		if event.StreamID() != 3 {
			t.Fatalf("next request = %v", event)
		}
	default:
		t.Fatal("driver consumed the next pipelined request")
	}
}

func TestDriverClientDisconnect(t *testing.T) {
	a := &streamAddon{}
	s, _ := newTestStream(t, a)
	client, server := newFakeClient(), newFakeServer()
	client.events <- requestHead("3")
	close(client.events)
	d := &streamDriver{stream: s, client: client, server: server}
	if err := d.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(server.started)
	if diff := gocmp.Diff([]string{"requestheaders", "error"}, a.calls); diff != "" {
		t.Fatal(diff)
	}
	responses := client.responses()
	if len(responses) != 1 {
		t.Fatalf("client events = %v", eventTypes(responseEventsAsEvents(responses)))
	}
	failure := responses[0].(ResponseProtocolError)
	if failure.Code != ClientDisconnected || failure.Message != "peer closed connection" {
		t.Fatalf("disconnect error = %+v", failure)
	}
}
