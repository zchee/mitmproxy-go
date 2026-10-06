// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// streamOutput separates a transition's wire output from its continuation.
// The owner sends every event before calling after, on the same goroutine.
// In particular, the final transform bytes must precede the completed-body
// hook, while trailers must follow that hook. Neither step performs I/O.
// The other direction may make progress while these events are being sent.
type streamOutput struct {
	events []Event
	after  func(context.Context) (streamOutput, error)
}

type streamBody struct {
	headers   bool
	streaming bool
	ending    bool
	done      bool
	body      []byte
	trailers  httpmsg.Headers
	transform func([]byte) [][]byte
}

// httpStream is owned by one goroutine. Only flow is shared with addons;
// snapshot and the two body states belong exclusively to the owner.
type httpStream struct {
	c             *layer.Context
	id            StreamID
	route         routeConfig
	wire          *wireStore
	flow          *flow.HTTPFlow
	snapshot      *layer.Snapshot
	request       streamBody
	response      streamBody
	upgrade       websocketHandshake
	h2c           *h2.UpgradeRequest
	seededUpgrade bool

	requestSent    bool
	responseHook   bool
	errorHook      bool
	failed         bool
	connectRequest bool
	priorKnowledge bool
	clientClosed   func() bool
	// clientTerminal is notified by readers; cancel wakes an intercepted hook.
	clientTerminal context.Context
	cancel         context.CancelCauseFunc
	// connectEstablished reports the stream answered a CONNECT with a 2xx:
	// the connection now belongs to a child protocol, not to HTTP.
	connectEstablished bool
	// connectConn and connectServer hold the connection the eager strategy
	// opened while answering a CONNECT, for the layer to publish to the
	// child; the handler's pool still owns the transport.
	connectConn   layer.Conn
	connectServer *connection.Server
}

func (s *httpStream) done() bool {
	return s.failed || s.request.done && s.response.done
}

func (s *httpStream) handle(ctx context.Context, event Event) (streamOutput, error) {
	if event.StreamID() != s.id {
		return streamOutput{}, fmt.Errorf("HTTP stream %d received event for stream %d", s.id, event.StreamID())
	}
	if s.failed {
		return streamOutput{}, nil
	}
	switch event := event.(type) {
	case RequestHeaders:
		return s.requestHeaders(ctx, event)
	case ResponseHeaders:
		return s.responseHeaders(ctx, event)
	case RequestData:
		return s.data(ctx, true, event.Data)
	case ResponseData:
		return s.data(ctx, false, event.Data)
	case RequestTrailers:
		return s.trailers(true, event.Trailers)
	case ResponseTrailers:
		return s.trailers(false, event.Trailers)
	case RequestEndOfMessage:
		return s.end(ctx, true)
	case ResponseEndOfMessage:
		return s.end(ctx, false)
	case RequestProtocolError:
		return s.fail(ctx, event.Message, event.Code)
	case ResponseProtocolError:
		return s.fail(ctx, event.Message, event.Code)
	default:
		return streamOutput{}, fmt.Errorf("unsupported HTTP event %T", event)
	}
}

func (s *httpStream) requestHeaders(ctx context.Context, event RequestHeaders) (streamOutput, error) {
	if s.request.headers || event.Request == nil {
		return streamOutput{}, fmt.Errorf("HTTP stream %d received invalid request headers", s.id)
	}
	if s.seededUpgrade {
		var request *httpmsg.Request
		if err := s.c.Do(ctx, func(context.Context) error { request = s.flow.Request.Clone(); return nil }); err != nil {
			return streamOutput{}, err
		}
		s.snapshot = &layer.Snapshot{Request: request, Live: true}
		s.request.headers, s.requestSent = true, true
		s.request.streaming = !event.EndStream
		return streamOutput{events: []Event{RequestHeaders{ID: s.id, Request: request.Clone(), EndStream: event.EndStream}}}, nil
	}
	if err := s.c.Do(ctx, func(context.Context) error {
		if event.ReplayFlow != nil {
			s.flow = event.ReplayFlow
		} else {
			s.flow = flow.NewHTTPFlow(s.c.Data.Client, s.c.Data.Server, true)
		}
		return nil
	}); err != nil {
		return streamOutput{}, err
	}
	s.request.headers = true
	if strings.EqualFold(event.Request.Headers.Get("Upgrade"), "websocket") {
		s.upgrade.clientRequest = event.Request.Clone()
	}

	if message := validateRequest(s.route.mode, event.Request, s.route.validateInboundHeaders); message != "" {
		// The head parsed, so handlers see the flow before the refusal, as
		// upstream registers it with the requestheaders hook first.
		var err error
		s.snapshot, err = s.fireHook(ctx, func(context.Context) error {
			s.flow.Request = event.Request
			s.flow.Request.RawContent = nil
			return nil
		}, addon.RequestHeadersHook{Flow: s.flow})
		if err != nil {
			return streamOutput{}, err
		}
		return s.fail(ctx, message, RequestValidationFailed)
	}
	if event.Request.Method == "CONNECT" {
		return s.handleConnect(ctx, event)
	}
	// The cleartext preface remains visible to request hooks, so the default
	// rejection addon can kill it before any HTTP/2 endpoint is selected.
	s.priorKnowledge = event.Request.Method == "PRI" && event.Request.Path == "*" && event.Request.HTTPVersion == "HTTP/2.0"
	if s.priorKnowledge {
		var err error
		s.snapshot, err = s.fireHook(ctx, func(context.Context) error {
			s.flow.Request = event.Request
			return nil
		}, addon.RequestHeadersHook{Flow: s.flow})
		return streamOutput{}, err
	}
	var clientTLS bool
	var server connection.Server
	if err := s.c.Do(ctx, func(context.Context) error {
		clientTLS = s.c.Data.Client.TLS
		server = *s.c.Data.Server
		if server.Address != nil {
			// Own the address: another exchange may rewrite the shared
			// metadata while this one normalizes outside the lock.
			address := *server.Address
			server.Address = &address
		}
		return nil
	}); err != nil {
		return streamOutput{}, err
	}
	if message := normalizeRequest(s.route, clientTLS, &server, event.Request); message != "" {
		// Upstream refuses without registering the flow or firing hooks:
		// nothing useful can be shown without a destination.
		s.failed = true
		return streamOutput{events: []Event{ResponseProtocolError{ID: s.id, Message: message, Code: DestinationUnknown}}}, nil
	}

	size, _ := http1.ExpectedBodySize(event.Request, nil)
	tooLarge, stream, err := s.checkSize(size.Length)
	if err != nil {
		return streamOutput{}, err
	}
	s.snapshot, err = s.fireHook(ctx, func(context.Context) error {
		s.flow.Request = event.Request
		s.flow.Request.RawContent = nil
		if stream && !event.EndStream {
			s.flow.Request.Stream = true
		}
		return nil
	}, addon.RequestHeadersHook{Flow: s.flow})
	if err != nil {
		return streamOutput{}, err
	}
	if s.snapshot.Killed() {
		return s.fail(ctx, s.snapshot.Error.Msg, Kill)
	}
	if tooLarge && !event.EndStream {
		return s.bodyTooLarge(ctx, true)
	}
	request := s.snapshot.Request
	var events []Event
	if strings.EqualFold(request.Headers.Get("Expect"), "100-continue") {
		events = append(events, ResponseHeaders{ID: s.id, EndStream: true, Response: &httpmsg.Response{
			HTTPVersion: "HTTP/1.1", StatusCode: 100, Reason: "Continue", RawContent: []byte{},
		}})
		if err := s.c.Do(ctx, func(context.Context) error {
			s.flow.Request.Headers.Del("Expect")
			return nil
		}); err != nil {
			return streamOutput{}, err
		}
		request.Headers.Del("Expect")
	}
	s.request.streaming = !event.EndStream && (request.Stream || request.StreamFunc != nil)
	s.request.transform = request.StreamFunc
	if s.request.streaming {
		s.requestSent = true
		events = append(events, RequestHeaders{ID: s.id, Request: request.Clone()})
	}
	return streamOutput{events: events}, nil
}

func (s *httpStream) responseHeaders(ctx context.Context, event ResponseHeaders) (streamOutput, error) {
	if !s.requestSent || s.response.headers || event.Response == nil {
		return streamOutput{}, fmt.Errorf("HTTP stream %d received invalid response headers", s.id)
	}
	if event.Response.StatusCode == 101 {
		s.upgrade.serverResponse = event.Response.Clone()
	}
	if s.route.validateInboundHeaders {
		if err := event.Response.ValidateHeaders(); err != nil {
			message := fmt.Sprintf("Received %v from server, refusing to prevent request smuggling attacks. "+
				"Disable the validate_inbound_headers option to skip this security check.", err)
			if err := s.c.Do(ctx, func(context.Context) error {
				s.flow.Response = event.Response
				s.flow.Response.RawContent = nil
				return nil
			}); err != nil {
				return streamOutput{}, err
			}
			// Retire the origin before error hooks, which may pause the flow.
			s.failed = true
			return streamOutput{
				events: []Event{RequestProtocolError{ID: s.id, Message: message, Code: ResponseValidationFailed}},
				after: func(ctx context.Context) (streamOutput, error) {
					out, err := s.fail(ctx, message, ResponseValidationFailed)
					if err == nil {
						// Only the client error remains; the origin is already retired.
						out.events = out.events[:1]
					}
					return out, err
				},
			}, nil
		}
	}
	if event.Response.StatusCode >= 100 && event.Response.StatusCode < 200 && event.Response.StatusCode != 101 {
		return streamOutput{events: []Event{event}}, nil
	}
	s.response.headers = true
	size, _ := http1.ExpectedBodySize(s.snapshot.Request, event.Response)
	tooLarge, stream, err := s.checkSize(size.Length)
	if err != nil {
		return streamOutput{}, err
	}
	s.snapshot, err = s.fireHook(ctx, func(context.Context) error {
		s.flow.Response = event.Response
		s.flow.Response.RawContent = nil
		if stream && !event.EndStream {
			s.flow.Response.Stream = true
		}
		return nil
	}, addon.ResponseHeadersHook{Flow: s.flow})
	if err != nil {
		return streamOutput{}, err
	}
	if s.snapshot.Killed() {
		return s.fail(ctx, s.snapshot.Error.Msg, Kill)
	}
	if tooLarge && !event.EndStream {
		return s.bodyTooLarge(ctx, false)
	}
	response := s.snapshot.Response
	s.response.streaming = !event.EndStream && (response.Stream || response.StreamFunc != nil)
	s.response.transform = response.StreamFunc
	if s.response.streaming {
		return streamOutput{events: []Event{ResponseHeaders{ID: s.id, Response: response.Clone()}}}, nil
	}
	return streamOutput{}, nil
}

func (s *httpStream) body(request bool) *streamBody {
	if request {
		return &s.request
	}
	return &s.response
}

func (s *httpStream) data(ctx context.Context, request bool, data []byte) (streamOutput, error) {
	body := s.body(request)
	if !body.headers || body.ending || body.done || body.trailers != nil || len(data) == 0 {
		return streamOutput{}, fmt.Errorf("HTTP stream %d received unexpected body data", s.id)
	}
	if request && s.seededUpgrade {
		return streamOutput{events: []Event{RequestData{ID: s.id, Data: data}}}, nil
	}
	if body.streaming {
		return s.transform(ctx, request, data)
	}
	// Check before allocating: a declared size is never used to preallocate,
	// and even one oversized event must not be copied into the body buffer.
	tooLarge, stream, err := s.checkSize(int64(len(body.body)) + int64(len(data)))
	if err != nil {
		return streamOutput{}, err
	}
	if tooLarge {
		return s.bodyTooLarge(ctx, request)
	}
	body.body = append(body.body, data...)
	if !stream {
		return streamOutput{}, nil
	}
	body.streaming = true
	if err := s.c.Do(ctx, func(context.Context) error {
		if request {
			s.flow.Request.Stream = true
		} else {
			s.flow.Response.Stream = true
		}
		return nil
	}); err != nil {
		return streamOutput{}, err
	}
	var head Event
	if request {
		s.snapshot.Request.Stream = true
		s.requestSent = true
		head = RequestHeaders{ID: s.id, Request: s.snapshot.Request.Clone()}
	} else {
		s.snapshot.Response.Stream = true
		head = ResponseHeaders{ID: s.id, Response: s.snapshot.Response.Clone()}
	}
	buffered := body.body
	body.body = nil
	out, err := s.transform(ctx, request, buffered)
	out.events = append([]Event{head}, out.events...)
	return out, err
}

func (s *httpStream) transform(ctx context.Context, request bool, data []byte) (streamOutput, error) {
	body := s.body(request)
	chunks := [][]byte{data}
	if body.transform != nil {
		if err := s.c.Do(ctx, func(context.Context) error {
			transformed := body.transform(data)
			chunks = make([][]byte, 0, len(transformed))
			for _, chunk := range transformed {
				if len(chunk) != 0 {
					// A callback may reuse its own buffers on its next call.
					chunks = append(chunks, bytes.Clone(chunk))
				}
			}
			return nil
		}); err != nil {
			return streamOutput{}, err
		}
	}
	out := streamOutput{}
	store := s.c.Data.Options.Bool("store_streamed_bodies")
	for _, chunk := range chunks {
		if len(chunk) == 0 {
			continue
		}
		if store {
			body.body = append(body.body, chunk...)
		}
		if request {
			out.events = append(out.events, RequestData{ID: s.id, Data: chunk})
		} else {
			out.events = append(out.events, ResponseData{ID: s.id, Data: chunk})
		}
	}
	return out, nil
}

func (s *httpStream) trailers(request bool, trailers httpmsg.Headers) (streamOutput, error) {
	body := s.body(request)
	if !body.headers || body.ending || body.done || body.trailers != nil {
		return streamOutput{}, fmt.Errorf("HTTP stream %d received unexpected trailers", s.id)
	}
	body.trailers = trailers
	return streamOutput{}, nil
}

func (s *httpStream) end(ctx context.Context, request bool) (streamOutput, error) {
	body := s.body(request)
	if !body.headers || body.ending || body.done {
		return streamOutput{}, fmt.Errorf("HTTP stream %d received unexpected end of message", s.id)
	}
	body.ending = true
	if request && s.connectRequest {
		// CONNECT has its own hooks; HTTP completion is not a tunnel FIN.
		body.done = true
		return streamOutput{}, nil
	}
	if body.streaming {
		out, err := s.transform(ctx, request, []byte{})
		out.after = func(ctx context.Context) (streamOutput, error) { return s.finish(ctx, request) }
		return out, err
	}
	return s.finish(ctx, request)
}

func (s *httpStream) finish(ctx context.Context, request bool) (streamOutput, error) {
	if s.failed {
		return streamOutput{}, nil
	}
	body := s.body(request)
	if request && s.seededUpgrade {
		body.done = true
		return streamOutput{events: []Event{RequestEndOfMessage{ID: s.id}}}, nil
	}
	content := body.body
	body.body = nil
	if !body.streaming && content == nil {
		content = []byte{}
	}
	var hook addon.Hook = addon.ResponseHook{Flow: s.flow}
	if request {
		hook = addon.RequestHook{Flow: s.flow}
	} else {
		s.responseHook = true
	}
	var err error
	s.snapshot, err = s.fireHook(ctx, func(context.Context) error {
		message := &s.flow.Request.Message
		if !request {
			message = &s.flow.Response.Message
		}
		message.RawContent = content
		message.Trailers = body.trailers
		message.TimestampEnd = new(float64(time.Now().UnixNano()) / 1e9)
		return nil
	}, hook)
	if err != nil {
		return streamOutput{}, err
	}
	body.done = true
	body.trailers = nil
	if s.snapshot.Killed() {
		return s.fail(ctx, s.snapshot.Error.Msg, Kill)
	}
	if request && s.priorKnowledge {
		var enabled bool
		if err := s.c.Do(ctx, func(context.Context) error {
			enabled = !s.c.Data.Client.TLS && (!s.c.Data.Options.Has("http2") || s.c.Data.Options.Bool("http2"))
			return nil
		}); err != nil {
			return streamOutput{}, err
		}
		if !enabled {
			return s.fail(ctx, "Cleartext HTTP/2 is disabled.", GenericClientError)
		}
		s.response.done = true
		return streamOutput{}, s.notLive(ctx)
	}
	if request && s.snapshot.Response == nil && strings.EqualFold(s.snapshot.Request.Headers.Get("Upgrade"), "h2c") {
		var err error
		s.h2c, err = s.prepareH2C(ctx)
		if err != nil {
			return s.fail(ctx, err.Error(), GenericClientError)
		}
		if s.h2c != nil {
			s.response.done = true
			response := &httpmsg.Response{HTTPVersion: "HTTP/1.1", StatusCode: 101, Reason: "Switching Protocols", Headers: httpmsg.Headers{{Name: []byte("Connection"), Value: []byte("Upgrade")}, {Name: []byte("Upgrade"), Value: []byte("h2c")}}, RawContent: []byte{}}
			return streamOutput{events: []Event{ResponseHeaders{ID: s.id, Response: response, EndStream: true}, ResponseEndOfMessage{ID: s.id}}}, nil
		}
	}
	if request && s.snapshot.Response != nil && !s.response.headers {
		return s.syntheticResponse(ctx)
	}
	var out streamOutput
	if request {
		message := s.snapshot.Request
		if !body.streaming {
			s.requestSent = true
			out.events = append(out.events, RequestHeaders{ID: s.id, Request: message.Clone(), EndStream: len(message.RawContent) == 0 && message.Trailers == nil})
			if len(message.RawContent) != 0 {
				out.events = append(out.events, RequestData{ID: s.id, Data: message.RawContent})
			}
		}
		if message.Trailers != nil {
			out.events = append(out.events, RequestTrailers{ID: s.id, Trailers: message.Trailers})
		}
		out.events = append(out.events, RequestEndOfMessage{ID: s.id})
	} else {
		message := s.snapshot.Response
		if !body.streaming {
			out.events = append(out.events, ResponseHeaders{ID: s.id, Response: message.Clone(), EndStream: len(message.RawContent) == 0 && message.Trailers == nil})
			if len(message.RawContent) != 0 {
				out.events = append(out.events, ResponseData{ID: s.id, Data: message.RawContent})
			}
		}
		if message.Trailers != nil {
			out.events = append(out.events, ResponseTrailers{ID: s.id, Trailers: message.Trailers})
		}
		out.events = append(out.events, ResponseEndOfMessage{ID: s.id})
		if err := s.notLive(ctx); err != nil {
			return streamOutput{}, err
		}
	}
	return out, nil
}

func (s *httpStream) syntheticResponse(ctx context.Context) (streamOutput, error) {
	s.response.headers = true
	var err error
	s.snapshot, err = s.runHook(ctx, nil, addon.ResponseHeadersHook{Flow: s.flow})
	if err != nil {
		return streamOutput{}, err
	}
	if s.snapshot.Killed() {
		return s.fail(ctx, s.snapshot.Error.Msg, Kill)
	}
	s.response.body = s.snapshot.Response.RawContent
	s.response.trailers = s.snapshot.Response.Trailers
	return s.end(ctx, false)
}

func (s *httpStream) checkSize(size int64) (tooLarge, stream bool, err error) {
	if size <= 0 {
		return false, false, nil
	}
	limit, err := human.ParseOptSize(s.c.Data.Options.OptStr("body_size_limit"))
	if err != nil {
		return false, false, err
	}
	threshold, err := human.ParseOptSize(s.c.Data.Options.OptStr("stream_large_bodies"))
	if err != nil {
		return false, false, err
	}
	return limit != nil && size > *limit, threshold != nil && size > *threshold, nil
}

func (s *httpStream) bodyTooLarge(ctx context.Context, request bool) (streamOutput, error) {
	if request {
		return s.fail(ctx, "Request body exceeds mitmproxy's body_size_limit.", RequestTooLarge)
	}
	return s.fail(ctx, "Response body exceeds mitmproxy's body_size_limit.", ResponseTooLarge)
}

func (s *httpStream) fail(ctx context.Context, message string, code ErrorCode) (streamOutput, error) {
	s.failed = true
	s.request.body, s.response.body = nil, nil
	s.request.trailers, s.response.trailers = nil, nil
	if s.flow != nil && !s.errorHook && !s.responseHook {
		s.errorHook = true
		var err error
		s.snapshot, err = s.fireHook(ctx, func(context.Context) error {
			s.flow.Error = flow.NewError(message)
			return nil
		}, addon.ErrorHook{Flow: s.flow})
		if err != nil {
			return streamOutput{}, err
		}
		if s.snapshot.Killed() {
			code = Kill
		}
	}
	if s.flow != nil {
		if err := s.notLive(ctx); err != nil {
			return streamOutput{}, err
		}
	}
	out := streamOutput{events: []Event{ResponseProtocolError{ID: s.id, Message: message, Code: code}}}
	if s.requestSent {
		out.events = append(out.events, RequestProtocolError{ID: s.id, Message: message, Code: code})
	}
	return out, nil
}

func (s *httpStream) notLive(ctx context.Context) error {
	if err := s.c.Do(ctx, func(context.Context) error {
		s.flow.Live = false
		return nil
	}); err != nil {
		return err
	}
	if s.snapshot != nil {
		s.snapshot.Live = false
	}
	return nil
}
