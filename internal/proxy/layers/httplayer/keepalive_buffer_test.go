// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

// bufferWatchConn observes completed socket reads without replacing the real peer.
type bufferWatchConn struct {
	layer.Conn
	read chan struct{}
}

// SetReadDeadline observes the receiver's deadline reset under its state mutex.
func (c *bufferWatchConn) SetReadDeadline(deadline time.Time) error {
	err := c.Conn.SetReadDeadline(deadline)
	if deadline.IsZero() {
		select {
		case c.read <- struct{}{}:
		default:
		}
	}
	return err
}

func waitForHTTP1Buffer(t *testing.T, endpoint *http1Server, read <-chan struct{}, size int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), layertest.Timeout)
	defer cancel()
	for {
		select {
		case <-read:
			endpoint.mu.Lock()
			buffered, capacity, state := len(endpoint.waitBuf), cap(endpoint.waitBuf), endpoint.state
			endpoint.mu.Unlock()
			if buffered > layer.MaxRecordBytes || capacity > layer.MaxRecordBytes || state != http1Wait {
				t.Fatalf("pre-completion state: bytes=%d capacity=%d state=%d", buffered, capacity, state)
			}
			if buffered == size {
				return
			}
		case <-ctx.Done():
			t.Fatal("receiver did not reach the expected bounded buffer")
		}
	}
}

func TestHTTP1KeepAliveBuffer(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			method        string
			bytes         int
			responseBytes int
			overflow      bool
			close         bool
			cancel        bool
			run           func(*testing.T)
		}{
			"early_next_request_within_limit":    {bytes: 1024},
			"limit_backpressure_same_connection": {bytes: 1 << 20},
			"genuine_overflow_closes":            {method: "CONNECT", bytes: layer.MaxRecordBytes + 1, overflow: true},
			"pipelined_body_completion_order":    {bytes: 1 << 20, responseBytes: 1024},
			"connection_close_preserved":         {close: true},
			"bounded_wait_cancellation":          {bytes: 1 << 20, cancel: true},
			"connection_upgrade_token_refused": {run: func(t *testing.T) {
				for _, side := range []string{"request", "response"} {
					t.Logf("Connection upgrade token on %s", side)
					checkHTTP1LatePolicy(t, side)
				}
			}},
			"late_until_close_response_refused": {run: func(t *testing.T) {
				checkHTTP1LatePolicy(t, "until-close")
			}},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				if tt.run != nil {
					tt.run(t)
					return
				}
				conn, peer := layertest.Pipe(t)
				watch := &bufferWatchConn{Conn: conn, read: make(chan struct{}, 1)}
				endpoint := newHTTP1Server(watch, newWireStore(), nil)
				method := tt.method
				if method == "" {
					method = "GET"
				}
				writeAll(t, peer, method+" /first HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
				for range 2 {
					if _, err := endpoint.Receive(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
				if !tt.overflow {
					headers := httpmsg.Headers{{Name: []byte("Content-Length"), Value: fmt.Appendf(nil, "%d", tt.responseBytes)}}
					if tt.close {
						headers.Set("Connection", "close")
					}
					response := &httpmsg.Response{HTTPVersion: "HTTP/1.1", StatusCode: 200, Reason: "OK", Headers: headers}
					if err := endpoint.Send(t.Context(), ResponseHeaders{ID: 1, Response: response}); err != nil {
						t.Fatal(err)
					}
					if tt.responseBytes != 0 {
						if err := endpoint.Send(t.Context(), ResponseData{ID: 1, Data: bytes.Repeat([]byte("r"), tt.responseBytes)}); err != nil {
							t.Fatal(err)
						}
					}
					// Consume the complete length-framed response before its final
					// internal event, exactly when a normal client can send again.
					want := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n", tt.responseBytes)
					if tt.close {
						want += "Connection: close\r\n"
					}
					want += "\r\n" + strings.Repeat("r", tt.responseBytes)
					if diff := gocmp.Diff(want, readExactly(t, peer, len(want))); diff != "" {
						t.Fatalf("first response differs (-want +got):\n%s", diff)
					}
				}
				if tt.close {
					if err := endpoint.Send(t.Context(), ResponseEndOfMessage{ID: 1}); err != nil {
						t.Fatal(err)
					}
					if got := readToEOF(t, peer); got != "" || !endpoint.done() {
						t.Fatalf("Connection: close: bytes=%q done=%t", got, endpoint.done())
					}
					return
				}

				ctx, cancel := context.WithCancel(t.Context())
				var work sync.WaitGroup
				t.Cleanup(func() {
					cancel()
					_ = conn.Close()
					_ = peer.Close()
					work.Wait()
				})
				type received struct {
					event RequestEvent
					err   error
				}
				next := make(chan received, 1)
				work.Go(func() { event, err := endpoint.Receive(ctx); next <- received{event, err} })
				body := strings.Repeat("b", tt.bytes)
				wire := fmt.Sprintf("POST /next HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s", tt.bytes, body)
				if tt.overflow {
					wire = body
				}
				written := make(chan error, 1)
				work.Go(func() { _, err := io.WriteString(peer, wire); written <- err })
				if tt.overflow {
					got := <-next
					failure, ok := got.event.(RequestProtocolError)
					if got.err != nil || !ok || failure.Code != GenericClientError || !strings.Contains(failure.Message, "buffered more than") || !endpoint.done() {
						t.Fatalf("overflow: event=%#v error=%v done=%t", got.event, got.err, endpoint.done())
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					if len(endpoint.waitBuf) > layer.MaxRecordBytes || cap(endpoint.waitBuf) > layer.MaxRecordBytes {
						t.Fatal("overflow retained more than the fixed buffer bound")
					}
					if err := endpoint.Send(t.Context(), ResponseProtocolError{ID: 1, Code: GenericClientError, Message: failure.Message}); err != nil {
						t.Fatal(err)
					}
					if got := readToEOF(t, peer); !strings.Contains(got, "400 Bad Request") {
						t.Fatalf("overflow response did not close with a protocol error: %q", got)
					}
					return
				}

				waitForHTTP1Buffer(t, endpoint, watch.read, min(len(wire), layer.MaxRecordBytes))
				if tt.cancel {
					cancel()
					if got := <-next; !errors.Is(got.err, context.Canceled) {
						t.Fatalf("bounded wait cancellation: event=%#v error=%v", got.event, got.err)
					}
					_ = peer.Close()
					<-written
					return
				}
				if tt.bytes > layer.MaxRecordBytes {
					// A full receiver owns no global lock: another real connection
					// can complete its response while this one is backpressured.
					otherConn, otherPeer := layertest.Pipe(t)
					other := newHTTP1Server(otherConn, newWireStore(), nil)
					writeAll(t, otherPeer, "GET / HTTP/1.1\r\n\r\n")
					for range 2 {
						if _, err := other.Receive(t.Context()); err != nil {
							t.Fatal(err)
						}
					}
					for _, event := range []ResponseEvent{ResponseHeaders{ID: 1, Response: mustResponse(t, 200, nil)}, ResponseEndOfMessage{ID: 1}} {
						if err := other.Send(t.Context(), event); err != nil {
							t.Fatal(err)
						}
					}
					readExactly(t, otherPeer, len(response200))
				}
				if err := endpoint.Send(t.Context(), ResponseEndOfMessage{ID: 1}); err != nil {
					t.Fatal(err)
				}
				got := <-next
				head, ok := got.event.(RequestHeaders)
				if got.err != nil || !ok || head.ID != 3 || head.Request.Method != "POST" || endpoint.done() {
					t.Fatalf("same-connection next request: event=%#v error=%v done=%t", got.event, got.err, endpoint.done())
				}
				var receivedBody strings.Builder
				for {
					event, err := endpoint.Receive(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if data, ok := event.(RequestData); ok {
						receivedBody.Write(data.Data)
					}
					if end, ok := event.(RequestEndOfMessage); ok {
						if end.ID != 3 {
							t.Fatalf("next request stream=%d, want 3", end.ID)
						}
						break
					}
				}
				if diff := gocmp.Diff(body, receivedBody.String()); diff != "" {
					t.Fatalf("next request body differs (-want +got):\n%s", diff)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
			})
		}
	})
}

func checkHTTP1LatePolicy(t *testing.T, policy string) {
	t.Helper()
	conn, peer := layertest.Pipe(t)
	watch := &bufferWatchConn{Conn: conn, read: make(chan struct{}, 1)}
	endpoint := newHTTP1Server(watch, newWireStore(), nil)
	ctx, cancel := context.WithTimeout(t.Context(), layertest.Timeout)
	var work sync.WaitGroup
	defer func() {
		cancel()
		_ = conn.Close()
		_ = peer.Close()
		work.Wait()
	}()
	request := "GET / HTTP/1.1\r\nContent-Length: 0\r\n"
	if policy == "request" {
		request += "Connection: keep-alive, UpGrAdE\r\n"
	}
	writeAll(t, peer, request+"\r\n")
	for range 2 {
		if _, err := endpoint.Receive(ctx); err != nil {
			t.Fatal(err)
		}
	}
	type received struct {
		event RequestEvent
		err   error
	}
	next := make(chan received, 1)
	work.Go(func() { event, err := endpoint.Receive(ctx); next <- received{event, err} })
	written := make(chan error, 1)
	work.Go(func() { _, err := io.WriteString(peer, strings.Repeat("b", layer.MaxRecordBytes+1)); written <- err })
	if policy != "request" {
		// No response metadata exists yet: prove a full reusable wait is
		// released when the real response makes this exchange non-reusable.
		waitForHTTP1Buffer(t, endpoint, watch.read, layer.MaxRecordBytes)
		response := &httpmsg.Response{HTTPVersion: "HTTP/1.1", StatusCode: 200, Reason: "OK"}
		if policy == "response" {
			response.Headers = httpmsg.Headers{
				{Name: []byte("Content-Length"), Value: []byte("0")},
				{Name: []byte("Connection"), Value: []byte("keep-alive, UpGrAdE")},
			}
		}
		if err := endpoint.Send(ctx, ResponseHeaders{ID: 1, Response: response}); err != nil {
			t.Fatal(err)
		}
	}
	var got received
	select {
	case got = <-next:
	case <-ctx.Done():
		t.Fatalf("%s policy did not release the bounded waiter: %v", policy, ctx.Err())
	}
	failure, ok := got.event.(RequestProtocolError)
	if got.err != nil || !ok || failure.Code != GenericClientError || !strings.Contains(failure.Message, "buffered more than") || !endpoint.done() {
		t.Fatalf("%s overflow: event=%#v error=%v done=%t", policy, got.event, got.err, endpoint.done())
	}
	if len(endpoint.waitBuf) != layer.MaxRecordBytes || cap(endpoint.waitBuf) > layer.MaxRecordBytes {
		t.Fatalf("%s retained bytes=%d capacity=%d", policy, len(endpoint.waitBuf), cap(endpoint.waitBuf))
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Send(ctx, ResponseProtocolError{ID: 1, Code: GenericClientError, Message: failure.Message}); err != nil {
		t.Fatal(err)
	}
	if got := readToEOF(t, peer); got == "" {
		t.Fatalf("%s overflow did not finish and close the response", policy)
	}
}
