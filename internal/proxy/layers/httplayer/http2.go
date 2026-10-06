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

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/version"
)

// HTTP exchange identities stay connection-scoped; each wire endpoint keeps its
// own stream identity even when the other endpoint uses HTTP/1.
type http2Stream struct {
	engine      *h2.Endpoint
	identity    layer.StreamIdentity
	id          StreamID
	normalize   bool
	logger      *slog.Logger
	clock       layer.Clock
	queue       []Event
	receipt     layer.ConsumptionReceipt
	receivedEnd bool
	sentHeaders bool
	sentEnd     bool
}

func (s *http2Stream) takeReceipt() layer.ConsumptionReceipt {
	receipt := s.receipt
	s.receipt = nil
	return receipt
}

func (s *http2Stream) waitSendCredit(ctx context.Context) error {
	return s.engine.WaitSendCredit(ctx, s.identity)
}

func (s *http2Stream) needsReadCredit() bool {
	return len(s.queue) == 0 && !s.receivedEnd
}

func (s *http2Stream) waitStreamDone(context.Context) <-chan struct{} {
	return s.engine.StreamDone(s.identity)
}

func (s *http2Stream) receive(ctx context.Context, request bool, head *h2.Event) (Event, error) {
	if len(s.queue) != 0 {
		event := s.queue[0]
		s.queue[0] = nil
		s.queue = s.queue[1:]
		return event, nil
	}
	if s.receivedEnd {
		return nil, io.EOF
	}
	for {
		var wire h2.Event
		var err error
		if head != nil {
			wire = *head
			head = nil
		} else {
			wire, err = s.engine.ReceiveStream(ctx, s.identity)
		}
		if err != nil {
			return nil, err
		}
		var event Event
		switch wire.Kind {
		case h2.Headers:
			clock := s.clock
			if clock == nil {
				clock = layer.WallClock
			}
			started := float64(clock.Now().UnixNano()) / 1e9
			if request {
				message, err := parseH2RequestHeaders(wire.Headers)
				if err != nil {
					message := "Invalid HTTP/2 request headers: " + err.Error()
					if err := s.engine.Shutdown(ctx, http2.ErrCodeProtocol, []byte(message)); err != nil {
						return nil, errors.Join(errors.New(message), err)
					}
					return RequestProtocolError{ID: s.id, Message: message, Code: GenericClientError}, nil
				}
				message.TimestampStart = started
				event = RequestHeaders{ID: s.id, Request: message, EndStream: wire.EndStream}
			} else {
				message, err := parseH2ResponseHeaders(wire.Headers)
				if err != nil {
					message := "Invalid HTTP/2 response headers: " + err.Error()
					if err := s.engine.Shutdown(ctx, http2.ErrCodeProtocol, []byte(message)); err != nil {
						return nil, errors.Join(errors.New(message), err)
					}
					return ResponseProtocolError{ID: s.id, Message: message, Code: GenericServerError}, nil
				}
				message.TimestampStart = started
				event = ResponseHeaders{ID: s.id, Response: message, EndStream: wire.EndStream}
			}
		case h2.Informational:
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
				s.logger.Info(fmt.Sprintf("Swallowing HTTP/2 informational response: %s %s", status, reason))
			}
			continue
		case h2.Data:
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
		case h2.Trailers:
			if request {
				event = RequestTrailers{ID: s.id, Trailers: h2RegularHeaders(wire.Headers)}
			} else {
				event = ResponseTrailers{ID: s.id, Trailers: h2RegularHeaders(wire.Headers)}
			}
		case h2.Reset:
			s.receivedEnd = true
			code := GenericServerError
			if request {
				code = GenericClientError
			}
			switch wire.Code {
			case http2.ErrCodeCancel:
				code = Cancel
			case http2.ErrCodeHTTP11Required:
				code = HTTP11Required
			}
			name := wire.Code.String()
			if wire.Code > http2.ErrCodeHTTP11Required {
				name = strconv.FormatUint(uint64(wire.Code), 10)
			}
			message := fmt.Sprintf("stream reset by client (%s)", name)
			if request {
				return RequestProtocolError{ID: s.id, Message: message, Code: code}, nil
			}
			return ResponseProtocolError{ID: s.id, Message: message, Code: code}, nil
		default:
			return nil, fmt.Errorf("unexpected HTTP/2 stream event: %d", wire.Kind)
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
			s.queue = append(s.queue, end)
		}
		if event != nil {
			return event, nil
		}
	}
}

func h2ResetCode(code ErrorCode) http2.ErrCode {
	switch code {
	case Cancel, ClientDisconnected, PassthroughClose:
		return http2.ErrCodeCancel
	case HTTP11Required:
		return http2.ErrCodeHTTP11Required
	default:
		return http2.ErrCodeInternal
	}
}

func (s *http2Stream) send(ctx context.Context, event Event) error {
	wire := h2.Event{Identity: s.identity}
	switch event := event.(type) {
	case RequestProtocolError:
		return s.engine.CancelStream(s.identity, h2ResetCode(event.Code))
	case ResponseProtocolError:
		status, respond := event.Code.HTTPStatusCode()
		if !s.sentHeaders && respond {
			body := formatError(status, event.Message)
			if err := s.engine.Send(ctx, h2.Event{Kind: h2.Headers, Identity: s.identity, Headers: []hpack.HeaderField{{Name: ":status", Value: fmt.Sprint(status)}, {Name: "server", Value: version.String()}, {Name: "content-type", Value: "text/html"}}}); err != nil {
				return err
			}
			s.sentHeaders, s.sentEnd = true, true
			return s.engine.Send(ctx, h2.Event{Kind: h2.Data, Identity: s.identity, Data: body, EndStream: true})
		}
		return s.engine.CancelStream(s.identity, h2ResetCode(event.Code))
	case RequestHeaders:
		wire.Kind, wire.Headers, wire.EndStream = h2.Headers, formatH2RequestHeaders(event.Request, s.normalize, s.logger), event.EndStream
	case ResponseHeaders:
		wire.Kind, wire.Headers, wire.EndStream = h2.Headers, formatH2ResponseHeaders(event.Response, s.normalize, s.logger), event.EndStream
	case RequestData:
		wire.Kind, wire.Data = h2.Data, event.Data
	case ResponseData:
		wire.Kind, wire.Data = h2.Data, event.Data
	case RequestTrailers:
		wire.Kind, wire.Headers, wire.EndStream = h2.Trailers, formatH2RegularHeaders(event.Trailers, true, s.normalize, s.logger), true
	case ResponseTrailers:
		wire.Kind, wire.Headers, wire.EndStream = h2.Trailers, formatH2RegularHeaders(event.Trailers, true, s.normalize, s.logger), true
	case RequestEndOfMessage, ResponseEndOfMessage:
		wire.Kind, wire.EndStream = h2.Data, true
	default:
		return fmt.Errorf("unsupported HTTP/2 send event %T", event)
	}
	if s.sentEnd {
		return nil
	}
	if err := s.engine.Send(ctx, wire); err != nil {
		return err
	}
	if wire.Kind == h2.Headers {
		s.sentHeaders = true
	}
	s.sentEnd = wire.EndStream
	return nil
}

type http2Client struct{ http2Stream }

func (c *http2Client) Receive(ctx context.Context) (ResponseEvent, error) {
	event, err := c.receive(ctx, false, nil)
	if err != nil {
		return nil, err
	}
	return event.(ResponseEvent), nil
}

func (c *http2Client) Send(ctx context.Context, event RequestEvent) error { return c.send(ctx, event) }

type http2Server struct {
	http2Stream
	head *h2.Event
}

func (s *http2Server) Receive(ctx context.Context) (RequestEvent, error) {
	head := s.head
	s.head = nil
	event, err := s.receive(ctx, true, head)
	if err != nil {
		return nil, err
	}
	return event.(RequestEvent), nil
}

func (s *http2Server) Send(ctx context.Context, event ResponseEvent) error { return s.send(ctx, event) }

func h2StreamFailure(err error, fallback ErrorCode) ErrorCode {
	if stream, ok := errors.AsType[*h2.StreamError](err); ok {
		switch stream.Code {
		case http2.ErrCodeCancel:
			return Cancel
		case http2.ErrCodeHTTP11Required:
			return HTTP11Required
		}
	}
	return fallback
}
