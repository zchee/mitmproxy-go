// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"fmt"
	"strconv"

	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/internal/human"
)

// Response is an HTTP response.
type Response struct {
	Message
	// StatusCode is the HTTP status code, for example 200.
	StatusCode int
	// Reason is the reason phrase as received, for example "Not Found".
	// Upstream decodes it as Latin-1 for display. HTTP/2 and HTTP/3
	// responses have none.
	Reason string
}

// MakeResponse builds an HTTP/1.1 response with the given status, body and
// headers, setting the standard reason phrase and Content-Length, as
// upstream's Response.make does.
func MakeResponse(statusCode int, content []byte, headers Headers) (*Response, error) {
	now := state.Now()
	r := &Response{
		HTTPVersion:    "HTTP/1.1",
		Headers:        headers,
		TimestampStart: now,
		TimestampEnd:   &now,
		StatusCode:     statusCode,
		Reason:         StatusText(statusCode),
	}
	if r.Headers == nil {
		r.Headers = Headers{}
	}
	if content == nil {
		content = []byte{}
	}
	r.SetContent(content)
	return r, nil
}

// String formats r like upstream, for example
// "Response(200, text/html, 1.2k)" or "Response(204, no content)".
func (r *Response) String() string {
	if len(r.RawContent) == 0 {
		return fmt.Sprintf("Response(%d, no content)", r.StatusCode)
	}
	ct, ok := r.Headers.Lookup("content-type")
	if !ok {
		ct = "unknown content type"
	}
	return fmt.Sprintf("Response(%d, %s, %s)", r.StatusCode, ct, human.PrettySize(int64(len(r.RawContent))))
}

func itoa(i int) string { return strconv.Itoa(i) }

// GetState returns r's serialised state.
func (r *Response) GetState() *state.Map {
	m := state.NewMap(8)
	r.putState(m)
	m.Set("status_code", int64(r.StatusCode))
	m.Set("reason", []byte(r.Reason))
	return m
}

// SetState replaces r's fields with those in m, consuming m. On error r is
// left unchanged.
func (r *Response) SetState(m *state.Map) error {
	d := state.NewDecoder(m, "Response")
	var n Response
	n.readState(d)
	n.StatusCode = int(d.Int("status_code"))
	n.Reason = string(d.Bytes("reason"))
	if err := d.Finish(); err != nil {
		return err
	}
	*r = n
	return nil
}

// ResponseFromState returns a new Response built from m, consuming m.
func ResponseFromState(m *state.Map) (*Response, error) {
	r := &Response{}
	if err := r.SetState(m); err != nil {
		return nil, err
	}
	return r, nil
}

// Clone returns a deep copy of r.
func (r *Response) Clone() *Response {
	out := *r
	out.Message = r.clone()
	return &out
}
