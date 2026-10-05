// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package httplayer connects HTTP protocol endpoints through a common
// request/response event vocabulary.
package httplayer

import (
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// StreamID identifies a request/response exchange. It is scoped to the
// client connection and shared by both endpoints; zero is a valid ID.
// Protocol endpoints translate it to their own wire stream identifiers.
type StreamID uint64

// Event is one HTTP message event. Only this package's event types implement
// it; endpoints for different wire protocols use the same vocabulary.
// Events carry owned data, not views into a reusable transport buffer.
type Event interface {
	// StreamID identifies the exchange to which this event belongs.
	StreamID() StreamID
	isHTTPEvent()
}

// RequestEvent travels from the client toward the server.
type RequestEvent interface {
	Event
	isRequestEvent()
}

// ResponseEvent travels from the server toward the client.
type ResponseEvent interface {
	Event
	isResponseEvent()
}

// RequestHeaders starts a request. EndStream promises an empty body, but a
// RequestEndOfMessage still follows. ReplayFlow, when non-nil, identifies
// the existing flow to reuse for a replayed request; access to that flow
// remains subject to the dispatch-lock rules.
type RequestHeaders struct {
	ID         StreamID
	Request    *httpmsg.Request
	EndStream  bool
	ReplayFlow *flow.HTTPFlow
}

// ResponseHeaders starts a response. Informational responses other than
// 101 precede the final ResponseHeaders without ending the exchange.
// EndStream promises an empty body; ResponseEndOfMessage still follows.
type ResponseHeaders struct {
	ID        StreamID
	Response  *httpmsg.Response
	EndStream bool
}

// RequestData carries a nonempty, transfer-decoded request body chunk.
// Content-Encoding is preserved; chunk boundaries need not match wire frames.
type RequestData struct {
	ID   StreamID
	Data []byte
}

// ResponseData carries a nonempty, transfer-decoded response body chunk.
// Content-Encoding is preserved; chunk boundaries need not match wire frames.
type ResponseData struct {
	ID   StreamID
	Data []byte
}

// RequestTrailers carries ordered request trailers after the last data
// event and before RequestEndOfMessage.
type RequestTrailers struct {
	ID       StreamID
	Trailers httpmsg.Headers
}

// ResponseTrailers carries ordered response trailers after the last data
// event and before ResponseEndOfMessage.
type ResponseTrailers struct {
	ID       StreamID
	Trailers httpmsg.Headers
}

// RequestEndOfMessage ends a request, including one with EndStream set.
// For CONNECT it completes the HTTP message, not the tunnel's write direction.
type RequestEndOfMessage struct {
	ID StreamID
}

// ResponseEndOfMessage ends the final response, including one with EndStream set.
// A successful CONNECT or 101 ends its HTTP message before the separately
// negotiated tunnel or upgrade begins; this event does not close that transport.
type ResponseEndOfMessage struct {
	ID StreamID
}

// RequestProtocolError terminates a request. Code must be set explicitly.
// Message is the upstream-compatible explanation, not a formatted HTTP body.
type RequestProtocolError struct {
	ID      StreamID
	Message string
	Code    ErrorCode
}

// ResponseProtocolError terminates a response. Code must be set explicitly.
// Message is the upstream-compatible explanation, not a formatted HTTP body.
type ResponseProtocolError struct {
	ID      StreamID
	Message string
	Code    ErrorCode
}

// StreamID returns the exchange identity.
func (e RequestHeaders) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e ResponseHeaders) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e RequestData) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e ResponseData) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e RequestTrailers) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e ResponseTrailers) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e RequestEndOfMessage) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e ResponseEndOfMessage) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e RequestProtocolError) StreamID() StreamID { return e.ID }

// StreamID returns the exchange identity.
func (e ResponseProtocolError) StreamID() StreamID { return e.ID }

func (RequestHeaders) isHTTPEvent()            {}
func (ResponseHeaders) isHTTPEvent()           {}
func (RequestData) isHTTPEvent()               {}
func (ResponseData) isHTTPEvent()              {}
func (RequestTrailers) isHTTPEvent()           {}
func (ResponseTrailers) isHTTPEvent()          {}
func (RequestEndOfMessage) isHTTPEvent()       {}
func (ResponseEndOfMessage) isHTTPEvent()      {}
func (RequestProtocolError) isHTTPEvent()      {}
func (ResponseProtocolError) isHTTPEvent()     {}
func (RequestHeaders) isRequestEvent()         {}
func (RequestData) isRequestEvent()            {}
func (RequestTrailers) isRequestEvent()        {}
func (RequestEndOfMessage) isRequestEvent()    {}
func (RequestProtocolError) isRequestEvent()   {}
func (ResponseHeaders) isResponseEvent()       {}
func (ResponseData) isResponseEvent()          {}
func (ResponseTrailers) isResponseEvent()      {}
func (ResponseEndOfMessage) isResponseEvent()  {}
func (ResponseProtocolError) isResponseEvent() {}

// ErrorCode classifies an HTTP stream failure using mitmproxy's event codes.
// HTTPStatusCode maps GenericClientError, RequestValidationFailed and
// DestinationUnknown to 400; RequestTooLarge to 413; ConnectFailed,
// GenericServerError, ResponseValidationFailed and ResponseTooLarge to 502.
// PassthroughClose, Kill, HTTP11Required, ClientDisconnected and Cancel
// close or reset the stream without an HTTP error response.
type ErrorCode uint8

const (
	// GenericClientError is a malformed request.
	GenericClientError ErrorCode = iota + 1
	// GenericServerError is a malformed response.
	GenericServerError
	// RequestTooLarge means the request exceeds the configured body limit.
	RequestTooLarge
	// ResponseTooLarge means the response exceeds the configured body limit.
	ResponseTooLarge
	// ConnectFailed means the upstream connection could not be established.
	ConnectFailed
	// PassthroughClose ends an upgraded byte stream.
	PassthroughClose
	// Kill means an addon killed the flow.
	Kill
	// HTTP11Required asks the client to retry using HTTP/1.1.
	HTTP11Required
	// DestinationUnknown means the proxy cannot determine the request target.
	DestinationUnknown
	// ClientDisconnected means the client left before receiving the response.
	ClientDisconnected
	// Cancel means a peer cancelled a multiplexed stream.
	Cancel
	// RequestValidationFailed means the request failed HTTP validation.
	RequestValidationFailed
	// ResponseValidationFailed means the response failed HTTP validation.
	ResponseValidationFailed
)

// HTTPStatusCode returns the HTTP error status for c. It returns (0, false)
// when no HTTP response should be sent, including for an unknown code.
func (c ErrorCode) HTTPStatusCode() (int, bool) {
	switch c {
	case GenericClientError, RequestValidationFailed, DestinationUnknown:
		return 400, true
	case RequestTooLarge:
		return 413, true
	case ConnectFailed, GenericServerError, ResponseValidationFailed, ResponseTooLarge:
		return 502, true
	default:
		return 0, false
	}
}
