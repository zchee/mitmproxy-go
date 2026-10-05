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
	"time"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// http1Server speaks HTTP/1 toward the client, one exchange at a time, as
// upstream's Http1Server does: it parses requests into request events and
// writes response events back. Pipelined bytes stay buffered until the
// current exchange finishes. After a 101 upgrade or a CONNECT success it
// relays raw bytes, or the routing layer calls takeover instead and hands
// the remaining bytes to a child layer. Stream IDs are 1, 3, 5, as upstream.
type http1Server struct {
	http1Conn

	// Receive-side state, owned by the receiving goroutine.
	body  *http1.BodyReader
	queue []RequestEvent

	// id is the current stream. Guarded by mu: the next-exchange bump runs
	// under the lock, possibly on the sending goroutine.
	id StreamID

	// Send-side state, owned by the sending goroutine.
	sentHead     bool
	sentChunked  bool
	sentTrailers httpmsg.Headers
}

func newHTTP1Server(conn layer.Conn, wire *wireStore, fidelity *http1.FidelityCounter) *http1Server {
	return &http1Server{http1Conn: newHTTP1Conn(conn, wire, fidelity), id: 1}
}

func (s *http1Server) streamID() StreamID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

var _ ClientEndpoint = (*http1Server)(nil)

// Receive returns the next request event. See ClientEndpoint.
func (s *http1Server) Receive(ctx context.Context) (RequestEvent, error) {
	for {
		if len(s.queue) != 0 {
			event := s.queue[0]
			s.queue[0] = nil
			s.queue = s.queue[1:]
			return event, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		state := s.state
		s.mu.Unlock()
		var err error
		switch state {
		case http1Headers:
			err = s.readHead(ctx)
		case http1Body:
			err = s.readBody(ctx)
		case http1Wait:
			err = s.readWait(ctx)
		case http1Pipe:
			err = s.readPipe(ctx)
		case http1Done:
			return nil, io.EOF
		}
		if err != nil {
			return nil, err
		}
	}
}

func (s *http1Server) readHead(ctx context.Context) error {
	s.mu.Lock()
	if len(s.waitBuf) != 0 {
		// Bytes buffered while the previous exchange finished are the start
		// of this one, whichever goroutine made the state transition.
		s.src.push(s.waitBuf)
		s.waitBuf = nil
	}
	s.mu.Unlock()
	id := s.streamID()
	var head http1.RequestHead
	_, err := s.readCtx(ctx, func() (int, error) {
		var err error
		head, err = http1.ReadRequestHead(s.br)
		return 0, err
	})
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		// As upstream, a connection dropped inside a request head produces
		// no stream: the head never became visible to handlers.
		s.finish()
		return fmt.Errorf("client closed connection before completing request headers: %w", err)
	case errors.Is(err, io.EOF):
		s.finish()
		return io.EOF
	case err != nil && (errors.Is(err, http1.ErrInvalidHead) || errors.Is(err, http1.ErrHeadTooLarge) ||
		errors.Is(err, http1.ErrLineTooLong) || errors.Is(err, http1.ErrTooManyHeaders) ||
		errors.Is(err, http1.ErrChunkLineTooLong)):
		s.finish()
		s.queue = append(s.queue, RequestProtocolError{ID: id, Code: GenericClientError, Message: errorMessage(err)})
		return nil
	case err != nil:
		s.finish()
		return err
	}

	pristine := head.Request.Clone()
	size, err := http1.ExpectedBodySize(head.Request, nil)
	if err != nil {
		// The head parsed, so handlers get to see it before the error ends
		// the stream, as upstream shows such requests in the UI.
		s.finish()
		s.queue = append(s.queue,
			RequestHeaders{ID: id, Request: head.Request},
			RequestProtocolError{ID: id, Code: GenericClientError, Message: errorMessage(err)})
		return nil
	}
	s.wire.putRequest(id, &requestWire{head: &head, pristine: pristine})
	s.mu.Lock()
	s.request = pristine
	s.mu.Unlock()

	endStream := size.Mode == http1.BodyNone || size.Mode == http1.BodyLength && size.Length == 0
	s.queue = append(s.queue, RequestHeaders{ID: id, Request: head.Request, EndStream: endStream})
	s.body, err = http1.NewBodyReader(s.br, size)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.state = http1Body
	s.mu.Unlock()
	return nil
}

func (s *http1Server) readBody(ctx context.Context) error {
	id := s.streamID()
	buf := make([]byte, http1BodyChunk)
	n, err := s.readCtx(ctx, func() (int, error) { return s.body.Read(buf) })
	if n > 0 {
		s.queue = append(s.queue, RequestData{ID: id, Data: buf[:n:n]})
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF):
		if trailers := s.body.Trailers(); trailers != nil {
			s.queue = append(s.queue, RequestTrailers{ID: id, Trailers: trailers})
		}
		s.body = nil
		s.mu.Lock()
		connect := strings.ToUpper(s.request.Method) == "CONNECT"
		s.markDoneLocked(true, false, true)
		closing := s.state == http1Done && s.responseDone
		s.mu.Unlock()
		if closing {
			// The response was fully sent before the upload finished and the
			// connection carries no further exchange: nothing is owed to the
			// client, so announce the closure.
			s.closeWrite()
		}
		if !connect {
			// A CONNECT request has no end of message, as upstream: the
			// exchange turns into a byte stream instead of completing.
			s.queue = append(s.queue, RequestEndOfMessage{ID: id})
		}
		return nil
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		s.finish()
		s.queue = append(s.queue, RequestProtocolError{
			ID: id, Code: GenericClientError,
			Message: "HTTP/1 protocol error: " + errorMessage(err),
		})
		return nil
	}
}

// readWait buffers bytes that arrive before the exchange finishes: the next
// pipelined request, or tunnel bytes sent ahead of a CONNECT response. It
// returns to the caller only on a state change, a disconnect or an error.
func (s *http1Server) readWait(ctx context.Context) error {
	for {
		s.mu.Lock()
		if s.state != http1Wait {
			// readHead and readPipe claim the buffered bytes themselves.
			s.mu.Unlock()
			return nil
		}
		if err := s.drainBuffered(); err != nil {
			s.state = http1Done
			id := s.id
			s.mu.Unlock()
			s.queue = append(s.queue, RequestProtocolError{ID: id, Code: GenericClientError, Message: err.Error()})
			return nil
		}
		s.waiting = true
		room := layer.MaxRecordBytes - len(s.waitBuf) + 1
		s.mu.Unlock()

		buf := make([]byte, min(http1BodyChunk, room))
		n, err := s.readCtx(ctx, func() (int, error) { return s.br.Read(buf) })

		s.mu.Lock()
		s.waiting = false
		if n > 0 {
			s.waitBuf = append(s.waitBuf, buf[:n]...)
		}
		over := len(s.waitBuf) > layer.MaxRecordBytes
		if over {
			s.state = http1Done
		}
		state := s.state
		id := s.id
		s.mu.Unlock()
		if over {
			s.queue = append(s.queue, RequestProtocolError{
				ID: id, Code: GenericClientError,
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
			_ = s.conn.SetReadDeadline(time.Time{})
		case errors.Is(err, io.EOF):
			if state == http1Pipe {
				continue
			}
			// A peer that sent a FIN no longer wants our response.
			s.finish()
			s.queue = append(s.queue, RequestProtocolError{ID: s.streamID(), Code: ClientDisconnected, Message: "Client disconnected."})
			return nil
		default:
			s.finish()
			return err
		}
	}
}

func (s *http1Server) readPipe(ctx context.Context) error {
	s.mu.Lock()
	id := s.id
	if len(s.waitBuf) != 0 {
		data := s.takeWaitBufLocked()
		s.mu.Unlock()
		if len(data) != 0 {
			s.queue = append(s.queue, RequestData{ID: id, Data: data})
			return nil
		}
		s.mu.Lock()
	}
	s.mu.Unlock()
	buf := make([]byte, http1BodyChunk)
	n, err := s.readCtx(ctx, func() (int, error) { return s.br.Read(buf) })
	if n > 0 {
		s.queue = append(s.queue, RequestData{ID: id, Data: buf[:n:n]})
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF):
		s.finish()
		s.queue = append(s.queue, RequestEndOfMessage{ID: id})
		return nil
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		s.finish()
		return err
	}
}

// finish retires the connection: no further messages are parsed.
func (s *http1Server) finish() {
	s.mu.Lock()
	s.state = http1Done
	id := s.id
	s.mu.Unlock()
	s.wire.drop(id)
}

// Send writes one response event to the client. See ClientEndpoint.
func (s *http1Server) Send(ctx context.Context, event ResponseEvent) error {
	if err := s.acquireSend(ctx); err != nil {
		return err
	}
	defer s.releaseSend()
	s.mu.Lock()
	id := s.id
	pipe := s.state == http1Pipe
	s.mu.Unlock()
	if event.StreamID() != id {
		return fmt.Errorf("HTTP/1 response for stream %d while serving stream %d", event.StreamID(), id)
	}
	switch event := event.(type) {
	case ResponseHeaders:
		if event.Response == nil {
			return errors.New("HTTP/1 response headers without a response")
		}
		return s.sendHead(ctx, event.Response)
	case ResponseData:
		if pipe {
			return s.writeCtx(ctx, event.Data)
		}
		return s.writeData(ctx, s.sentChunked, event.Data)
	case ResponseTrailers:
		// Send only borrows the event: keep an owned copy for the terminal chunk.
		s.sentTrailers = event.Trailers.Clone()
		return nil
	case ResponseEndOfMessage:
		if pipe {
			s.closeWrite()
			return nil
		}
		return s.sendEnd(ctx)
	case ResponseProtocolError:
		return s.sendError(ctx, event)
	default:
		return fmt.Errorf("unsupported HTTP/1 response event %T", event)
	}
}

func (s *http1Server) sendHead(ctx context.Context, response *httpmsg.Response) error {
	var original *http1.ResponseHead
	addonChanged := false
	if entry := s.wire.takeResponse(s.streamID()); entry != nil {
		original = entry.head
		addonChanged = responseChanged(entry.pristine, response)
	}
	raw := http1.AssembleResponseHead(response, original, addonChanged, s.fidelity)
	if err := s.writeCtx(ctx, raw); err != nil {
		return err
	}
	if response.StatusCode >= 100 && response.StatusCode < 200 && response.StatusCode != 101 {
		// An informational response precedes the final head.
		return nil
	}
	s.sentHead = true
	s.sentChunked = chunkedTE(response.Headers)
	s.mu.Lock()
	s.response = response.Clone()
	s.mu.Unlock()
	return nil
}

func (s *http1Server) sendEnd(ctx context.Context) error {
	s.mu.Lock()
	request := s.request
	s.mu.Unlock()
	if !s.sentHead || request == nil {
		return errors.New("HTTP/1 response ended before its headers")
	}
	if s.sentChunked && strings.ToUpper(request.Method) != "HEAD" {
		if err := s.writeLastChunk(ctx, s.sentTrailers); err != nil {
			return err
		}
	}
	s.sentHead = false
	s.sentChunked = false
	s.sentTrailers = nil
	s.mu.Lock()
	s.markDoneLocked(false, true, false)
	closing := s.state == http1Done
	s.mu.Unlock()
	if closing {
		s.closeWrite()
	}
	return nil
}

func (s *http1Server) sendError(ctx context.Context, event ResponseProtocolError) error {
	s.mu.Lock()
	writable := !s.writeClosed
	s.state = http1Done
	id := s.id
	s.kick()
	s.mu.Unlock()
	s.wire.drop(id)
	if !writable {
		return nil
	}
	if status, ok := event.Code.HTTPStatusCode(); ok && !s.sentHead {
		response, err := makeErrorResponse(status, event.Message)
		if err != nil {
			return err
		}
		raw := http1.AssembleResponseHead(response, nil, false, nil)
		raw = append(raw, response.RawContent...)
		if err := s.writeCtx(ctx, raw); err != nil {
			return err
		}
	}
	s.closeWrite()
	return nil
}

// markDoneLocked records one finished direction and, when both are done,
// decides the connection's future: raw relay, closure, or the next exchange.
// onReceive says the call runs on the receive goroutine, the owner of the
// parser input; only that side may drain it at a pipe switch. The caller
// holds mu.
func (s *http1Server) markDoneLocked(request, response, onReceive bool) {
	if request {
		s.requestDone = true
	}
	if response {
		s.responseDone = true
	}
	if !s.requestDone || !s.responseDone {
		if s.requestDone {
			s.state = http1Wait
		}
		return
	}
	s.wire.drop(s.id)
	if shouldMakePipe(s.request, s.response) {
		if onReceive {
			if err := s.drainBuffered(); err != nil {
				s.state = http1Done
				return
			}
		}
		s.startPipe()
		return
	}
	if connectionDone(s.request, s.response, false) {
		s.state = http1Done
		s.kick()
		return
	}
	s.requestDone, s.responseDone = false, false
	s.request, s.response = nil, nil
	s.id += 2
	s.state = http1Headers
	s.kick()
}

// takeover retires the endpoint and returns the bytes it consumed beyond the
// finished exchange, stripped of superfluous leading newlines, so the routing
// layer can hand them with the transport to a child layer. The receive side
// must not be running concurrently.
func (s *http1Server) takeover() []byte {
	s.mu.Lock()
	s.state = http1Done
	buffered := s.waitBuf
	s.waitBuf = nil
	s.mu.Unlock()
	for {
		n := s.br.Buffered()
		if n == 0 {
			break
		}
		chunk, err := s.br.Peek(n)
		if err != nil {
			break
		}
		buffered = append(buffered, chunk...)
		if _, err := s.br.Discard(n); err != nil {
			break
		}
	}
	buffered = append(buffered, s.src.prefix...)
	s.src.prefix = nil
	return bytes.TrimLeft(buffered, "\r\n")
}
