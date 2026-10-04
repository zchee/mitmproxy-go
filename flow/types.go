// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// baseKeys is the number of keys Base.putState writes.
const baseKeys = 13

// HTTPFlow is one HTTP request/response pair. A flow may have both a
// response and an error, for example when the response arrived but could
// not be sent back to the client.
type HTTPFlow struct {
	Base
	// Request is the client's request.
	Request *httpmsg.Request
	// Response is the server's response, nil until one exists.
	Response *httpmsg.Response
	// WebSocket holds the WebSocket data when the flow upgraded to a
	// WebSocket connection, and is nil otherwise.
	WebSocket *websocket.Data
}

var _ Flow = (*HTTPFlow)(nil)

// NewHTTPFlow returns a new HTTP flow over the given connections.
func NewHTTPFlow(client *connection.Client, server *connection.Server, live bool) *HTTPFlow {
	return &HTTPFlow{Base: newBase(client, server, live)}
}

// Type returns "http".
func (f *HTTPFlow) Type() string { return "http" }

// TimestampStart returns the request's start timestamp, or 0 without a
// request.
func (f *HTTPFlow) TimestampStart() float64 {
	if f.Request == nil {
		return 0
	}
	return f.Request.TimestampStart
}

// GetState returns the flow's serialised state.
func (f *HTTPFlow) GetState() *state.Map {
	m := state.NewMap(baseKeys + 3)
	f.putState(m, f.Type())
	if f.Request != nil {
		m.Set("request", f.Request.GetState())
	} else {
		m.Set("request", nil)
	}
	if f.Response != nil {
		m.Set("response", f.Response.GetState())
	} else {
		m.Set("response", nil)
	}
	if f.WebSocket != nil {
		m.Set("websocket", f.WebSocket.GetState())
	} else {
		m.Set("websocket", nil)
	}
	return m
}

// SetState replaces the flow's fields with those in m, consuming m.
func (f *HTTPFlow) SetState(m *state.Map) error {
	d := state.NewDecoder(m, "HTTPFlow")
	var (
		req  *httpmsg.Request
		resp *httpmsg.Response
		ws   *websocket.Data
		err  error
	)
	if r := d.Dict("request"); r != nil {
		if req, err = httpmsg.RequestFromState(r); err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "request", err))
		}
	}
	if r := d.OptDict("response"); r != nil {
		if resp, err = httpmsg.ResponseFromState(r); err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "response", err))
		}
	}
	if w := d.OptDict("websocket"); w != nil {
		if ws, err = websocket.DataFromState(w); err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "websocket", err))
		}
	}
	base := f.readState(d, f.Type())
	if err := d.Finish(); err != nil {
		return err
	}
	f.Request, f.Response, f.WebSocket = req, resp, ws
	f.apply(base)
	return nil
}

// Copy returns an independent copy of the flow with a new ID.
func (f *HTTPFlow) Copy() Flow { return copyFlow(f) }

// Backup saves the current state for Revert.
func (f *HTTPFlow) Backup() { f.backupFrom(f) }

// Revert restores the state saved by Backup.
func (f *HTTPFlow) Revert() error { return f.revert(f) }

// Modified reports whether the flow differs from its backup.
func (f *HTTPFlow) Modified() bool { return f.modified(f) }

// TCPFlow is a TCP session, chunked into messages.
type TCPFlow struct {
	Base
	// Messages are the messages transmitted over the connection; the
	// latest is last.
	Messages []*tcp.Message
}

var _ Flow = (*TCPFlow)(nil)

// NewTCPFlow returns a new TCP flow over the given connections.
func NewTCPFlow(client *connection.Client, server *connection.Server, live bool) *TCPFlow {
	return &TCPFlow{Base: newBase(client, server, live), Messages: []*tcp.Message{}}
}

// Type returns "tcp".
func (f *TCPFlow) Type() string { return "tcp" }

// TimestampStart returns the client connection's start timestamp.
func (f *TCPFlow) TimestampStart() float64 { return f.clientStart() }

// String formats f like upstream, for example "<TCPFlow (3 messages)>".
func (f *TCPFlow) String() string {
	return fmt.Sprintf("<TCPFlow (%d messages)>", len(f.Messages))
}

// GetState returns the flow's serialised state.
func (f *TCPFlow) GetState() *state.Map {
	m := state.NewMap(baseKeys + 1)
	f.putState(m, f.Type())
	msgs := make([]any, len(f.Messages))
	for i, msg := range f.Messages {
		msgs[i] = msg.GetState()
	}
	m.Set("messages", msgs)
	return m
}

// SetState replaces the flow's fields with those in m, consuming m.
func (f *TCPFlow) SetState(m *state.Map) error {
	d := state.NewDecoder(m, "TCPFlow")
	msgs := decodeMessages(d, tcp.MessageFromState)
	base := f.readState(d, f.Type())
	if err := d.Finish(); err != nil {
		return err
	}
	f.Messages = msgs
	f.apply(base)
	return nil
}

// Copy returns an independent copy of the flow with a new ID.
func (f *TCPFlow) Copy() Flow { return copyFlow(f) }

// Backup saves the current state for Revert.
func (f *TCPFlow) Backup() { f.backupFrom(f) }

// Revert restores the state saved by Backup.
func (f *TCPFlow) Revert() error { return f.revert(f) }

// Modified reports whether the flow differs from its backup.
func (f *TCPFlow) Modified() bool { return f.modified(f) }

// UDPFlow is a UDP session; each message is one datagram.
type UDPFlow struct {
	Base
	// Messages are the datagrams transmitted over the connection; the
	// latest is last.
	Messages []*udp.Message
}

var _ Flow = (*UDPFlow)(nil)

// NewUDPFlow returns a new UDP flow over the given connections.
func NewUDPFlow(client *connection.Client, server *connection.Server, live bool) *UDPFlow {
	return &UDPFlow{Base: newBase(client, server, live), Messages: []*udp.Message{}}
}

// Type returns "udp".
func (f *UDPFlow) Type() string { return "udp" }

// TimestampStart returns the client connection's start timestamp.
func (f *UDPFlow) TimestampStart() float64 { return f.clientStart() }

// String formats f like upstream, for example "<UDPFlow (3 messages)>".
func (f *UDPFlow) String() string {
	return fmt.Sprintf("<UDPFlow (%d messages)>", len(f.Messages))
}

// GetState returns the flow's serialised state.
func (f *UDPFlow) GetState() *state.Map {
	m := state.NewMap(baseKeys + 1)
	f.putState(m, f.Type())
	msgs := make([]any, len(f.Messages))
	for i, msg := range f.Messages {
		msgs[i] = msg.GetState()
	}
	m.Set("messages", msgs)
	return m
}

// SetState replaces the flow's fields with those in m, consuming m.
func (f *UDPFlow) SetState(m *state.Map) error {
	d := state.NewDecoder(m, "UDPFlow")
	msgs := decodeMessages(d, udp.MessageFromState)
	base := f.readState(d, f.Type())
	if err := d.Finish(); err != nil {
		return err
	}
	f.Messages = msgs
	f.apply(base)
	return nil
}

// Copy returns an independent copy of the flow with a new ID.
func (f *UDPFlow) Copy() Flow { return copyFlow(f) }

// Backup saves the current state for Revert.
func (f *UDPFlow) Backup() { f.backupFrom(f) }

// Revert restores the state saved by Backup.
func (f *UDPFlow) Revert() error { return f.revert(f) }

// Modified reports whether the flow differs from its backup.
func (f *UDPFlow) Modified() bool { return f.modified(f) }

// DNSFlow is one DNS query and its response.
type DNSFlow struct {
	Base
	// Request is the DNS query.
	Request *dns.Message
	// Response is the DNS response, nil until one exists.
	Response *dns.Message
}

var _ Flow = (*DNSFlow)(nil)

// NewDNSFlow returns a new DNS flow over the given connections.
func NewDNSFlow(client *connection.Client, server *connection.Server, live bool) *DNSFlow {
	return &DNSFlow{Base: newBase(client, server, live)}
}

// Type returns "dns".
func (f *DNSFlow) Type() string { return "dns" }

// TimestampStart returns the client connection's start timestamp.
func (f *DNSFlow) TimestampStart() float64 { return f.clientStart() }

// GetState returns the flow's serialised state.
func (f *DNSFlow) GetState() *state.Map {
	m := state.NewMap(baseKeys + 2)
	f.putState(m, f.Type())
	if f.Request != nil {
		m.Set("request", f.Request.GetState())
	} else {
		m.Set("request", nil)
	}
	if f.Response != nil {
		m.Set("response", f.Response.GetState())
	} else {
		m.Set("response", nil)
	}
	return m
}

// SetState replaces the flow's fields with those in m, consuming m.
func (f *DNSFlow) SetState(m *state.Map) error {
	d := state.NewDecoder(m, "DNSFlow")
	var req, resp *dns.Message
	var err error
	if r := d.Dict("request"); r != nil {
		if req, err = dns.MessageFromState(r); err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "request", err))
		}
	}
	if r := d.OptDict("response"); r != nil {
		if resp, err = dns.MessageFromState(r); err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "response", err))
		}
	}
	base := f.readState(d, f.Type())
	if err := d.Finish(); err != nil {
		return err
	}
	f.Request, f.Response = req, resp
	f.apply(base)
	return nil
}

// Copy returns an independent copy of the flow with a new ID.
func (f *DNSFlow) Copy() Flow { return copyFlow(f) }

// Backup saves the current state for Revert.
func (f *DNSFlow) Backup() { f.backupFrom(f) }

// Revert restores the state saved by Backup.
func (f *DNSFlow) Revert() error { return f.revert(f) }

// Modified reports whether the flow differs from its backup.
func (f *DNSFlow) Modified() bool { return f.modified(f) }

// decodeMessages reads the "messages" list with f applied to each tuple.
func decodeMessages[T any](d *state.Decoder, f func(any) (T, error)) []T {
	v := d.Any("messages")
	if d.Err() != nil {
		return nil
	}
	l, err := state.ListOf(v, f)
	if err != nil {
		d.Fail(fmt.Errorf("field %q: %w", "messages", err))
	}
	return l
}
