// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync/atomic"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h3"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/version"
)

// The exchange identity is separate from the endpoint-scoped QUIC stream ID.
// Each receive owner retains at most one pending end event and one DATA receipt;
// the engine bounds all queued and borrowed bytes independently of QUIC credit.
type http3Stream struct {
	engine             *h3.Endpoint
	failureDone        <-chan struct{}
	identity           layer.StreamIdentity
	id                 StreamID
	normalize          bool
	logger             *slog.Logger
	clock              layer.Clock
	queue              []Event
	receipt            layer.ConsumptionReceipt
	receivedEnd        bool
	sentHeaders        bool
	sentEnd            bool
	initialSendFailure atomic.Pointer[error]
}

func (s *http3Stream) takeReceipt() layer.ConsumptionReceipt {
	receipt := s.receipt
	s.receipt = nil
	return receipt
}

func (s *http3Stream) needsReadCredit() bool { return len(s.queue) == 0 && !s.receivedEnd }

func (s *http3Stream) waitStreamFailed(context.Context) <-chan struct{} { return s.failureDone }

func (s *http3Stream) waitEndpointFailed(ctx context.Context) bool {
	select {
	case <-s.failureDone:
	case <-ctx.Done():
		return false
	}
	if s.initialSendFailure.Load() == nil {
		return true
	}
	// Retiring an unsent identity is local cleanup, not an origin disconnect.
	select {
	case <-s.engine.Done():
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *http3Stream) receiveFailure(ctx context.Context) error {
	event, err := s.engine.ReceiveStream(ctx, s.identity)
	if err != nil {
		return err
	}
	return event.Err
}

func (s *http3Stream) receive(ctx context.Context, request bool, head *h3.Event) (Event, error) {
	if len(s.queue) != 0 {
		event := s.queue[0]
		s.queue = nil
		return event, nil
	}
	if s.receivedEnd {
		return nil, io.EOF
	}
	for {
		var wire h3.Event
		var err error
		if head != nil {
			wire = *head
			head = nil
		} else {
			wire, err = s.engine.ReceiveStream(ctx, s.identity)
		}
		if failure := s.initialSendFailure.Load(); failure != nil {
			return nil, *failure
		}
		if err != nil {
			return nil, err
		}
		var event Event
		switch wire.Kind {
		case h3.Headers:
			clock := s.clock
			if clock == nil {
				clock = layer.WallClock
			}
			started := float64(clock.Now().UnixNano()) / 1e9
			if request {
				message, err := parseH3RequestHeaders(wire.Headers)
				if err != nil {
					diagnostic := "Invalid HTTP/3 request headers: " + err.Error()
					return nil, errors.Join(errors.New(diagnostic), s.engine.Shutdown(ctx, h3.ErrCodeGeneralProtocol, []byte(diagnostic)))
				}
				message.TimestampStart = started
				event = RequestHeaders{ID: s.id, Request: message, EndStream: wire.EndStream}
			} else {
				message, err := parseH3ResponseHeaders(wire.Headers)
				if err != nil {
					diagnostic := "Invalid HTTP/3 response headers: " + err.Error()
					return nil, errors.Join(errors.New(diagnostic), s.engine.Shutdown(ctx, h3.ErrCodeGeneralProtocol, []byte(diagnostic)))
				}
				message.TimestampStart = started
				event = ResponseHeaders{ID: s.id, Response: message, EndStream: wire.EndStream}
			}
		case h3.Informational:
			if s.logger != nil {
				status, reason := "<unknown status>", ""
				for _, field := range wire.Headers {
					if field.Name == ":status" {
						if code, err := strconv.Atoi(field.Value); err == nil {
							status, reason = strconv.Itoa(code), httpmsg.StatusText(code)
						}
						break
					}
				}
				// Match the HTTP/2 adapter's interim-response policy.
				s.logger.Info(fmt.Sprintf("Swallowing HTTP/2 informational response: %s %s", status, reason))
			}
			continue
		case h3.Data:
			if len(wire.Data) == 0 {
				if wire.Receipt != nil {
					wire.Receipt.Complete()
				}
			} else {
				s.receipt = wire.Receipt
				if request {
					event = RequestData{ID: s.id, Data: wire.Data}
				} else {
					event = ResponseData{ID: s.id, Data: wire.Data}
				}
			}
		case h3.Trailers:
			if request {
				event = RequestTrailers{ID: s.id, Trailers: h3RegularHeaders(wire.Headers)}
			} else {
				event = ResponseTrailers{ID: s.id, Trailers: h3RegularHeaders(wire.Headers)}
			}
		case h3.Reset:
			s.receivedEnd = true
			code := GenericServerError
			if request {
				code = GenericClientError
			}
			switch wire.Code {
			case h3.ErrCodeRequestCancelled:
				code = Cancel
			case h3.ErrCodeVersionFallback:
				code = HTTP11Required
			}
			// Upstream uses this label for both endpoint roles.
			// py:mitmproxy/proxy/layers/http/_http3.py:144-158.
			message := "stream closed by client (" + wire.Code.String() + ")"
			if request {
				return RequestProtocolError{ID: s.id, Message: message, Code: code, Cause: wire.Err}, nil
			}
			return ResponseProtocolError{ID: s.id, Message: message, Code: code, Cause: wire.Err}, nil
		default:
			return nil, fmt.Errorf("unexpected HTTP/3 stream event: %d", wire.Kind)
		}
		if wire.EndStream {
			s.receivedEnd = true
			var end Event = ResponseEndOfMessage{ID: s.id}
			if request {
				end = RequestEndOfMessage{ID: s.id}
			}
			if event == nil {
				return end, nil
			}
			s.queue = []Event{end}
		}
		if event != nil {
			return event, nil
		}
	}
}

func httpStreamFailure(err error, fallback ErrorCode) ErrorCode {
	if stream, ok := errors.AsType[*h3.StreamError](err); ok {
		switch stream.Code {
		case h3.ErrCodeRequestCancelled:
			return Cancel
		case h3.ErrCodeVersionFallback:
			return HTTP11Required
		}
	}
	return h2StreamFailure(err, fallback)
}

func h3ResetCode(code ErrorCode) h3.ErrorCode {
	switch code {
	case Cancel, ClientDisconnected, PassthroughClose:
		return h3.ErrCodeRequestCancelled
	case HTTP11Required:
		return h3.ErrCodeVersionFallback
	default:
		return h3.ErrCodeInternal
	}
}

func (s *http3Stream) send(ctx context.Context, event Event) error {
	wire := h3.Event{Identity: s.identity}
	switch event := event.(type) {
	case RequestProtocolError:
		return s.engine.CancelStream(s.identity, h3ResetCode(event.Code))
	case ResponseProtocolError:
		status, respond := event.Code.HTTPStatusCode()
		if !s.sentHeaders && respond {
			body := formatError(status, event.Message, event.Cause)
			if err := s.engine.Send(ctx, h3.Event{Kind: h3.Headers, Identity: s.identity, Headers: []h3.HeaderField{{Name: ":status", Value: strconv.Itoa(status)}, {Name: "server", Value: version.String()}, {Name: "content-type", Value: "text/html"}}}); err != nil {
				return err
			}
			s.sentHeaders, s.sentEnd = true, true
			return s.engine.Send(ctx, h3.Event{Kind: h3.Data, Identity: s.identity, Data: body, EndStream: true})
		}
		return s.engine.CancelStream(s.identity, h3ResetCode(event.Code))
	case RequestHeaders:
		wire.Kind, wire.Headers, wire.EndStream = h3.Headers, formatH3RequestHeaders(event.Request, s.normalize, s.logger), event.EndStream
	case ResponseHeaders:
		wire.Kind, wire.Headers, wire.EndStream = h3.Headers, formatH3ResponseHeaders(event.Response, s.normalize, s.logger), event.EndStream
		if event.Response.StatusCode >= 100 && event.Response.StatusCode < 200 {
			wire.Kind, wire.EndStream = h3.Informational, false
		}
	case RequestData:
		wire.Kind, wire.Data = h3.Data, event.Data
	case ResponseData:
		wire.Kind, wire.Data = h3.Data, event.Data
	case RequestTrailers:
		wire.Kind, wire.Headers, wire.EndStream = h3.Trailers, formatH3Trailers(event.Trailers), true
	case ResponseTrailers:
		wire.Kind, wire.Headers, wire.EndStream = h3.Trailers, formatH3Trailers(event.Trailers), true
	case RequestEndOfMessage, ResponseEndOfMessage:
		wire.Kind, wire.EndStream = h3.Data, true
	default:
		return fmt.Errorf("unsupported HTTP/3 send event %T", event)
	}
	if s.sentEnd {
		return nil
	}
	if err := s.engine.Send(ctx, wire); err != nil {
		if _, request := event.(RequestHeaders); request && !s.sentHeaders {
			s.initialSendFailure.Store(new(err))
			// Free the identity before an error hook can pause its exchange.
			return errors.Join(err, s.engine.CancelStream(s.identity, h3.ErrCodeRequestCancelled))
		}
		return err
	}
	if wire.Kind == h3.Headers {
		s.sentHeaders = true
	}
	s.sentEnd = wire.EndStream
	return nil
}

type http3Client struct{ http3Stream }

// Receive converts the next wire event to a response without invoking hooks.
func (c *http3Client) Receive(ctx context.Context) (ResponseEvent, error) {
	event, err := c.receive(ctx, false, nil)
	if err != nil {
		return nil, err
	}
	return event.(ResponseEvent), nil
}

// Send borrows the request event until its stream write completes.
func (c *http3Client) Send(ctx context.Context, event RequestEvent) error { return c.send(ctx, event) }

type http3Server struct {
	http3Stream
	head *h3.Event
}

// Receive consumes the initial request head before the stream's body events.
func (s *http3Server) Receive(ctx context.Context) (RequestEvent, error) {
	head := s.head
	s.head = nil
	event, err := s.receive(ctx, true, head)
	if err != nil {
		return nil, err
	}
	return event.(RequestEvent), nil
}

// Send borrows the response event until its stream write completes.
func (s *http3Server) Send(ctx context.Context, event ResponseEvent) error { return s.send(ctx, event) }

var (
	_ ClientEndpoint = (*http3Server)(nil)
	_ ServerEndpoint = (*http3Client)(nil)
)
