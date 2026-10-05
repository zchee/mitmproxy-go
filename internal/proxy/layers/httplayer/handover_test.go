// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

// heldReadConn delays returning real socket data until the response sender has
// retired the endpoint. This exercises a deadline kick racing a successful read.
type heldReadConn struct {
	layer.Conn
	reads   int
	read    chan struct{}
	release chan struct{}
}

func (c *heldReadConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.reads++
	if c.reads == 2 {
		close(c.read)
		<-c.release
	}
	return n, err
}

func TestHTTP1ConnectHandoverClearsReadDeadline(t *testing.T) {
	conn, peer := layertest.Pipe(t)
	held := &heldReadConn{Conn: conn, read: make(chan struct{}), release: make(chan struct{})}
	endpoint := newHTTP1Server(held, newWireStore(), nil)
	endpoint.handover = true
	write(t, peer, "CONNECT origin.test:443 HTTP/1.1\r\n\r\n")
	if event, err := endpoint.Receive(t.Context()); err != nil {
		t.Fatal(err)
	} else if _, ok := event.(RequestHeaders); !ok {
		t.Fatalf("first event = %T, want request headers", event)
	}
	response := &httpmsg.Response{HTTPVersion: "HTTP/1.1", StatusCode: 200, Reason: "Connection established"}
	if err := endpoint.Send(t.Context(), ResponseHeaders{ID: 1, Response: response}); err != nil {
		t.Fatal(err)
	}
	expectRead(t, peer, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan error, 1)
	go func() {
		_, err := endpoint.Receive(t.Context())
		done <- err
	}()
	write(t, peer, "immediate tunnel bytes")
	await(t, held.read)
	if err := endpoint.Send(t.Context(), ResponseEndOfMessage{ID: 1}); err != nil {
		close(held.release)
		t.Fatal(err)
	}
	close(held.release)
	if err := await(t, done); !errors.Is(err, io.EOF) {
		t.Fatalf("retired endpoint Receive = %v, want EOF", err)
	}
	child := prefixed(endpoint.takeover(), held)
	expectRead(t, child, "immediate tunnel bytes")
	write(t, peer, "later tunnel bytes")
	expectRead(t, child, "later tunnel bytes")
}

func TestHTTP1UpgradeHandoverClearsReadDeadline(t *testing.T) {
	conn, peer := layertest.Pipe(t)
	held := &heldReadConn{Conn: conn, read: make(chan struct{}), release: make(chan struct{})}
	endpoint := newHTTP1Client(held, newWireStore(), nil)
	request := &httpmsg.Request{Method: "GET", Path: "/", HTTPVersion: "HTTP/1.1"}
	if err := endpoint.Send(t.Context(), RequestHeaders{ID: 1, Request: request}); err != nil {
		t.Fatal(err)
	}
	expectRead(t, peer, "GET / HTTP/1.1\r\n\r\n")
	write(t, peer, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
	for range 2 {
		if _, err := endpoint.Receive(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan driverRead, 1)
	go func() {
		event, err := endpoint.Receive(t.Context())
		done <- driverRead{event: event, err: err}
	}()
	write(t, peer, "immediate upgrade bytes")
	await(t, held.read)
	if err := endpoint.Send(t.Context(), RequestEndOfMessage{ID: 1}); err != nil {
		close(held.release)
		t.Fatal(err)
	}
	close(held.release)
	result := await(t, done)
	if result.err != nil {
		t.Fatal(result.err)
	}
	want := ResponseData{ID: 1, Data: []byte("immediate upgrade bytes")}
	if diff := gocmp.Diff(want, result.event); diff != "" {
		t.Fatalf("upgrade event (-want +got):\n%s", diff)
	}
	child := prefixed(endpoint.takeover(), held)
	write(t, peer, "later upgrade bytes")
	expectRead(t, child, "later upgrade bytes")
}
