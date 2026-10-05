// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// http1Client speaks HTTP/1 toward a server, one exchange at a time, as
// upstream's Http1Client does: it writes request events to the wire and
// parses responses into response events. The stream is bound by the first
// RequestHeaders of an exchange; sending another stream's headers before the
// exchange finished is an error, as HTTP/1 cannot pipeline through a proxy.
// After a 101 upgrade or a CONNECT success it relays raw bytes.
type http1Client struct {
	http1Conn

	// Receive-side state, owned by the receiving goroutine.
	body  *http1.BodyReader
	queue []ResponseEvent

	// Send-side state, owned by the sending goroutine.
	sentChunked  bool
	sentUntilEOF bool
	sentTrailers httpmsg.Headers

	// singleUse forces one exchange per connection, as upstream does for
	// HTTP/2 and HTTP/3 requests proxied over HTTP/1. Guarded by mu.
	singleUse bool

	// id is the bound stream, valid while bound is true. Guarded by mu:
	// the receive side labels events with it.
	id    StreamID
	bound bool
}

func newHTTP1Client(conn layer.Conn, wire *wireStore, fidelity *http1.FidelityCounter) *http1Client {
	return &http1Client{http1Conn: newHTTP1Conn(conn, wire, fidelity)}
}

var _ ServerEndpoint = (*http1Client)(nil)

// Send writes one request event to the server. See ServerEndpoint.
func (c *http1Client) Send(ctx context.Context, event RequestEvent) error {
	if err := c.acquireSend(ctx); err != nil {
		return err
	}
	defer c.releaseSend()
	if _, failed := event.(RequestProtocolError); failed {
		// The exchange failed on the client's side: the connection carries
		// nothing further, so retire it and wake a parked receive.
		c.closeWrite()
		c.mu.Lock()
		c.state = http1Done
		c.kick()
		c.mu.Unlock()
		return nil
	}
	c.mu.Lock()
	if !c.bound {
		if _, headers := event.(RequestHeaders); !headers {
			c.mu.Unlock()
			return fmt.Errorf("HTTP/1 %T before request headers", event)
		}
		c.id, c.bound = event.StreamID(), true
	} else if event.StreamID() != c.id {
		c.mu.Unlock()
		return fmt.Errorf("HTTP/1 request for stream %d while stream %d is in flight", event.StreamID(), c.id)
	}
	pipe := c.state == http1Pipe
	c.mu.Unlock()

	switch event := event.(type) {
	case RequestHeaders:
		if event.Request == nil {
			return errors.New("HTTP/1 request headers without a request")
		}
		return c.sendHead(ctx, event.Request)
	case RequestData:
		if pipe {
			return c.writeCtx(ctx, event.Data)
		}
		return c.writeData(ctx, c.sentChunked, event.Data)
	case RequestTrailers:
		// Send only borrows the event: keep an owned copy for the terminal chunk.
		c.sentTrailers = event.Trailers.Clone()
		return nil
	case RequestEndOfMessage:
		if pipe {
			c.closeWrite()
			return nil
		}
		return c.sendEnd(ctx)
	default:
		return fmt.Errorf("unsupported HTTP/1 request event %T", event)
	}
}

func (c *http1Client) sendHead(ctx context.Context, request *httpmsg.Request) error {
	c.mu.Lock()
	if c.request != nil {
		id := c.id
		c.mu.Unlock()
		return fmt.Errorf("HTTP/1 duplicate request headers for stream %d", id)
	}
	c.request = request.Clone()
	c.singleUse = request.IsHTTP2() || request.IsHTTP3()
	id := c.id
	c.mu.Unlock()
	var original *http1.RequestHead
	addonChanged := false
	if entry := c.wire.takeRequest(id); entry != nil {
		original = entry.head
		addonChanged = entry.addonChanged
	}
	raw := http1.AssembleRequestHead(request, original, addonChanged, c.fidelity)
	if err := c.writeCtx(ctx, raw); err != nil {
		return err
	}
	c.sentChunked = chunkedTE(request.Headers)
	size, err := http1.ExpectedBodySize(request, nil)
	c.sentUntilEOF = err == nil && size.Mode == http1.BodyUntilClose
	return nil
}

func (c *http1Client) sendEnd(ctx context.Context) error {
	if c.sentChunked {
		if err := c.writeLastChunk(ctx, c.sentTrailers); err != nil {
			return err
		}
	} else if c.sentUntilEOF {
		// The server learns the body's end from the stream's end.
		c.closeWrite()
	}
	c.sentChunked = false
	c.sentUntilEOF = false
	c.sentTrailers = nil
	c.mu.Lock()
	c.markDoneLocked(true, false, false)
	closing := c.state == http1Done && c.responseDone
	c.mu.Unlock()
	if closing {
		// The response completed first and the connection carries no further
		// exchange: nothing more will be written, so announce the closure.
		c.closeWrite()
	}
	return nil
}

// Receive returns the next response event. See ServerEndpoint.
func (c *http1Client) Receive(ctx context.Context) (ResponseEvent, error) {
	return c.receive(ctx, false)
}

// receive can monitor a completed exchange for an origin disconnect without
// interpreting later bytes. The next exchange or upgrade owns those bytes.
func (c *http1Client) receive(ctx context.Context, completed bool) (ResponseEvent, error) {
	for {
		if len(c.queue) != 0 {
			event := c.queue[0]
			c.queue[0] = nil
			c.queue = c.queue[1:]
			return event, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		state := c.state
		c.mu.Unlock()
		var err error
		switch {
		case completed:
			err = c.readWait(ctx, true)
		case state == http1Headers:
			err = c.readHead(ctx)
		case state == http1Body:
			err = c.readBody(ctx)
		case state == http1Wait:
			err = c.readWait(ctx, false)
		case state == http1Pipe:
			err = c.readPipe(ctx)
		default:
			return nil, io.EOF
		}
		if err != nil {
			return nil, err
		}
	}
}

// readWait parks the receive side after the response finished while the
// request is still uploading: bytes that arrive now belong to the exchange's
// outcome, a raw relay after an upgrade, and are buffered uninterpreted. A
// server close here is a connection-level end that the caller maps to the
// stream's failure, as the server refused to wait for the rest of the upload.
func (c *http1Client) readWait(ctx context.Context, completed bool) error {
	for {
		c.mu.Lock()
		if c.state != http1Wait && !completed {
			// readHead and readPipe claim the buffered bytes themselves.
			c.mu.Unlock()
			return nil
		}
		if err := c.drainBuffered(); err != nil {
			c.state = http1Done
			id := c.id
			c.mu.Unlock()
			c.queue = append(c.queue, ResponseProtocolError{ID: id, Code: GenericServerError, Message: err.Error()})
			return nil
		}
		c.waiting = true
		room := layer.MaxRecordBytes - len(c.waitBuf) + 1
		c.mu.Unlock()

		buf := make([]byte, min(http1BodyChunk, room))
		n, err := c.readCtx(ctx, func() (int, error) { return c.br.Read(buf) })

		c.mu.Lock()
		c.waiting = false
		// A state-change kick can race a successful read. Clear it while
		// holding mu so no expired deadline survives into the next exchange.
		_ = c.conn.SetReadDeadline(time.Time{})
		if n > 0 {
			c.waitBuf = append(c.waitBuf, buf[:n]...)
		}
		over := len(c.waitBuf) > layer.MaxRecordBytes
		if over {
			c.state = http1Done
		}
		state := c.state
		id := c.id
		c.mu.Unlock()
		if over {
			c.queue = append(c.queue, ResponseProtocolError{
				ID: id, Code: GenericServerError,
				Message: fmt.Sprintf("HTTP/1 connection buffered more than %d bytes before the exchange completed", layer.MaxRecordBytes),
			})
			return nil
		}
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
			return err
		case isTimeout(err):
			// A kick: re-check the state with a cleared deadline.
		case errors.Is(err, io.EOF):
			if state == http1Pipe && !completed {
				continue
			}
			c.finish()
			return io.EOF
		default:
			c.finish()
			return err
		}
	}
}

func (c *http1Client) readHead(ctx context.Context) error {
	c.mu.Lock()
	if len(c.waitBuf) != 0 {
		// Bytes buffered while the previous exchange finished precede
		// whatever the socket delivers next.
		c.src.push(c.waitBuf)
		c.waitBuf = nil
	}
	c.mu.Unlock()
	var head http1.ResponseHead
	_, err := c.readCtx(ctx, func() (int, error) {
		var err error
		head, err = http1.ReadResponseHead(c.br)
		return 0, err
	})
	c.mu.Lock()
	id, inFlight := c.id, c.request != nil
	c.mu.Unlock()
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		c.finish()
		if !inFlight {
			return fmt.Errorf("unexpected data from server: %w", err)
		}
		// Upstream reports the buffered bytes here; this parser has consumed
		// them, so the message carries no reproduction of the data.
		c.queue = append(c.queue, ResponseProtocolError{ID: id, Code: GenericServerError, Message: "unexpected server response"})
		return nil
	case errors.Is(err, io.EOF):
		c.finish()
		if !inFlight {
			return io.EOF
		}
		// The server closed the connection to prevent the request.
		c.queue = append(c.queue, ResponseProtocolError{ID: id, Code: GenericServerError, Message: "server closed connection"})
		return nil
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return err
	case err != nil:
		c.finish()
		if !inFlight {
			return err
		}
		c.queue = append(c.queue, ResponseProtocolError{
			ID: id, Code: GenericServerError,
			Message: "Cannot parse HTTP response: " + errorMessage(err),
		})
		return nil
	}
	if !inFlight {
		c.finish()
		return errors.New("unexpected data from server")
	}

	pristine := head.Response.Clone()
	status := head.Response.StatusCode
	if status >= 100 && status < 200 && status != 101 {
		// An informational response is forwarded; the final head follows.
		c.wire.putResponse(id, &responseWire{head: &head})
		c.queue = append(c.queue, ResponseHeaders{ID: id, Response: head.Response, EndStream: true})
		return nil
	}
	c.mu.Lock()
	request := c.request
	c.mu.Unlock()
	size, err := http1.ExpectedBodySize(request, head.Response)
	if err != nil {
		c.finish()
		c.queue = append(c.queue, ResponseProtocolError{
			ID: id, Code: GenericServerError,
			Message: "Cannot parse HTTP response: " + errorMessage(err),
		})
		return nil
	}
	c.wire.putResponse(id, &responseWire{head: &head})
	c.mu.Lock()
	c.response = pristine
	c.state = http1Body
	c.mu.Unlock()

	endStream := size.Mode == http1.BodyNone || size.Mode == http1.BodyLength && size.Length == 0
	c.queue = append(c.queue, ResponseHeaders{ID: id, Response: head.Response, EndStream: endStream})
	c.body, err = http1.NewBodyReader(c.br, size)
	return err
}

func (c *http1Client) readBody(ctx context.Context) error {
	buf := make([]byte, http1BodyChunk)
	n, err := c.readCtx(ctx, func() (int, error) { return c.body.Read(buf) })
	c.mu.Lock()
	id := c.id
	c.mu.Unlock()
	if n > 0 {
		c.queue = append(c.queue, ResponseData{ID: id, Data: buf[:n:n]})
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF):
		if trailers := c.body.Trailers(); trailers != nil {
			c.queue = append(c.queue, ResponseTrailers{ID: id, Trailers: trailers})
		}
		c.body = nil
		c.mu.Lock()
		connect := strings.ToUpper(c.request.Method) == "CONNECT"
		c.markDoneLocked(false, true, true)
		closing := c.state == http1Done && c.requestDone
		c.mu.Unlock()
		if closing {
			// The connection carries no further exchange and the request was
			// fully written: announce that nothing more follows.
			c.closeWrite()
		}
		if !connect {
			// A successful CONNECT has no end of message, as upstream: the
			// exchange turns into a byte stream instead of completing.
			c.queue = append(c.queue, ResponseEndOfMessage{ID: id})
		}
		return nil
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		c.finish()
		c.queue = append(c.queue, ResponseProtocolError{
			ID: id, Code: GenericServerError,
			Message: "HTTP/1 protocol error: " + errorMessage(err),
		})
		return nil
	}
}

func (c *http1Client) readPipe(ctx context.Context) error {
	c.mu.Lock()
	id := c.id
	if len(c.waitBuf) != 0 {
		data := c.takeWaitBufLocked()
		c.mu.Unlock()
		if len(data) != 0 {
			c.queue = append(c.queue, ResponseData{ID: id, Data: data})
			return nil
		}
		c.mu.Lock()
	}
	c.mu.Unlock()
	buf := make([]byte, http1BodyChunk)
	n, err := c.readCtx(ctx, func() (int, error) { return c.br.Read(buf) })
	if n > 0 {
		c.queue = append(c.queue, ResponseData{ID: id, Data: buf[:n:n]})
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF):
		c.finish()
		c.queue = append(c.queue, ResponseEndOfMessage{ID: id})
		return nil
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		c.finish()
		return err
	}
}

// finish retires the connection: no further messages are parsed. Wire
// metadata this endpoint stored stays in place: the client-facing endpoint
// may still emit a response that was fully received before the failure, and
// it drops the stream's entries itself when the exchange ends.
func (c *http1Client) finish() {
	c.mu.Lock()
	c.state = http1Done
	c.mu.Unlock()
}

// markDoneLocked records one finished direction and, when both are done,
// decides the connection's future: raw relay, closure, or readiness for the
// next exchange. onReceive says the call runs on the receive goroutine, the
// owner of the parser input; only that side may drain it at a pipe switch.
// The caller holds mu.
func (c *http1Client) markDoneLocked(request, response, onReceive bool) {
	if request {
		c.requestDone = true
	}
	if response {
		c.responseDone = true
	}
	if !c.requestDone || !c.responseDone {
		if c.responseDone && c.state == http1Body {
			c.state = http1Wait
		}
		return
	}
	if shouldMakePipe(c.request, c.response) {
		// Bytes the parser buffered past the response head, such as tunnel
		// data sent with a CONNECT success, replay first in the raw stream.
		if onReceive {
			if err := c.drainBuffered(); err != nil {
				c.state = http1Done
				return
			}
		}
		c.startPipe()
		return
	}
	if connectionDone(c.request, c.response, c.singleUse) {
		c.state = http1Done
		c.kick()
		return
	}
	c.requestDone, c.responseDone = false, false
	c.request, c.response = nil, nil
	c.bound = false
	c.singleUse = false
	c.state = http1Headers
	c.kick()
}
