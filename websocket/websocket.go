// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package websocket holds the data of a WebSocket connection that started
// as an HTTP flow: its messages and how it was closed.
//
// WebSocket connections are HTTP flows whose websocket attribute is set;
// this package only defines the message type and the container. Their
// serialised state matches mitmproxy's flow format 21.
package websocket

import (
	"bytes"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/internal/state"
)

// Opcode is a WebSocket frame opcode as defined by RFC 6455, section 5.2.
type Opcode uint8

// Opcodes upstream accepts. Messages are assembled from Text and Binary
// frames; the others appear only on control or continuation frames.
const (
	OpContinuation Opcode = 0x0
	OpText         Opcode = 0x1
	OpBinary       Opcode = 0x2
	OpClose        Opcode = 0x8
	OpPing         Opcode = 0x9
	OpPong         Opcode = 0xA
)

// String returns the opcode name upstream uses, for example "TEXT".
func (o Opcode) String() string {
	switch o {
	case OpContinuation:
		return "CONTINUATION"
	case OpText:
		return "TEXT"
	case OpBinary:
		return "BINARY"
	case OpClose:
		return "CLOSE"
	case OpPing:
		return "PING"
	case OpPong:
		return "PONG"
	}
	return fmt.Sprintf("Opcode(%d)", uint8(o))
}

// Valid reports whether o is one of the opcodes RFC 6455 defines.
func (o Opcode) Valid() bool {
	switch o {
	case OpContinuation, OpText, OpBinary, OpClose, OpPing, OpPong:
		return true
	}
	return false
}

// Message is one WebSocket message. Fragmented messages are reassembled
// before they become a Message, and the content is always kept as bytes.
type Message struct {
	// Type is the opcode of the message's first frame.
	Type Opcode
	// FromClient reports whether the client sent the message.
	FromClient bool
	// Content is the message payload.
	Content []byte
	// Timestamp is when the message was received or created.
	Timestamp float64
	// Dropped reports whether the proxy did not forward the message.
	Dropped bool
	// Injected reports whether the proxy injected the message instead of
	// receiving it from a peer.
	Injected bool
}

// NewMessage returns a message created now.
func NewMessage(typ Opcode, fromClient bool, content []byte) *Message {
	return &Message{Type: typ, FromClient: fromClient, Content: content, Timestamp: state.Now()}
}

// IsText reports whether the message was assembled from Text frames.
func (m *Message) IsText() bool {
	return m.Type == OpText
}

func (m *Message) noText() error {
	name := m.Type.String()
	if m.Type.Valid() {
		name = name[:1] + string(bytes.ToLower([]byte(name[1:])))
	}
	return fmt.Errorf("%s WebSocket frames do not have a 'text' attribute", name)
}

// Text returns the content of a text message. It fails for other message
// types and for content that is not valid UTF-8.
func (m *Message) Text() (string, error) {
	if !m.IsText() {
		return "", m.noText()
	}
	if !utf8.Valid(m.Content) {
		return "", fmt.Errorf("websocket text message is not valid UTF-8")
	}
	return string(m.Content), nil
}

// SetText replaces the content of a text message. It fails for other
// message types.
func (m *Message) SetText(text string) error {
	if !m.IsText() {
		return m.noText()
	}
	m.Content = []byte(text)
	return nil
}

// Drop marks the message so that it is not forwarded to the other peer.
func (m *Message) Drop() {
	m.Dropped = true
}

// formatted returns the message prefixed with its direction, the form the
// body filters search.
func (m *Message) formatted() []byte {
	prefix := "[INCOMING] "
	if m.FromClient {
		prefix = "[OUTGOING] "
	}
	return append([]byte(prefix), m.Content...)
}

// GetState returns the message as upstream's state tuple
// (opcode, from_client, content, timestamp, dropped, injected).
func (m *Message) GetState() []any {
	return []any{int64(m.Type), m.FromClient, state.Bytes(m.Content), m.Timestamp, m.Dropped, m.Injected}
}

// SetState replaces m's fields from a state tuple. On error m is left
// unchanged.
func (m *Message) SetState(v any) error {
	n, err := messageFromState(v)
	if err != nil {
		return err
	}
	*m = *n
	return nil
}

// MessageFromState returns a new Message built from a state tuple.
func MessageFromState(v any) (*Message, error) {
	return messageFromState(v)
}

func messageFromState(v any) (*Message, error) {
	t, err := state.Tuple(v, 6)
	if err != nil {
		return nil, fmt.Errorf("WebSocketMessage.set_state: %w", err)
	}
	var m Message
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	op, err := state.AsInt(t[0])
	collect(err)
	if err == nil && (op < 0 || op > 0xff || !Opcode(op).Valid()) {
		collect(fmt.Errorf("%d is not a valid Opcode", op))
	}
	m.Type = Opcode(op)
	m.FromClient, err = state.AsBool(t[1])
	collect(err)
	m.Content, err = state.AsBytes(t[2])
	collect(err)
	m.Timestamp, err = state.AsFloat(t[3])
	collect(err)
	m.Dropped, err = state.AsBool(t[4])
	collect(err)
	m.Injected, err = state.AsBool(t[5])
	collect(err)
	if len(errs) > 0 {
		return nil, fmt.Errorf("WebSocketMessage.set_state: %w", errs[0])
	}
	return &m, nil
}

// Clone returns a deep copy of m.
func (m *Message) Clone() *Message {
	out := *m
	out.Content = slices.Clone(m.Content)
	return &out
}

// Data holds everything related to one WebSocket connection. It is
// reached through the websocket field of an HTTP flow.
type Data struct {
	// Messages are all messages transferred over the connection.
	Messages []*Message
	// ClosedByClient is true when the client closed the connection, false
	// when the server did, and nil while the connection is open.
	ClosedByClient *bool
	// CloseCode is the close code from RFC 6455, section 7.1.5.
	CloseCode *int
	// CloseReason is the close reason from RFC 6455, section 7.1.6.
	CloseReason *string
	// TimestampEnd is when the connection was closed.
	TimestampEnd *float64
}

// String formats d like upstream, for example "<WebSocketData (3 messages)>".
func (d *Data) String() string {
	return fmt.Sprintf("<WebSocketData (%d messages)>", len(d.Messages))
}

// FormattedMessages returns every message prefixed with "[OUTGOING] " or
// "[INCOMING] ", joined by newlines. The body filters search this text.
func (d *Data) FormattedMessages() []byte {
	parts := make([][]byte, len(d.Messages))
	for i, m := range d.Messages {
		parts[i] = m.formatted()
	}
	return bytes.Join(parts, []byte("\n"))
}

// GetState returns d's serialised state.
func (d *Data) GetState() *state.Map {
	msgs := make([]any, len(d.Messages))
	for i, m := range d.Messages {
		msgs[i] = m.GetState()
	}
	m := state.NewMap(5)
	m.Set("messages", msgs)
	m.Set("closed_by_client", state.Opt(d.ClosedByClient))
	m.Set("close_code", state.OptInt(d.CloseCode))
	m.Set("close_reason", state.Opt(d.CloseReason))
	m.Set("timestamp_end", state.Opt(d.TimestampEnd))
	return m
}

// SetState replaces d's fields with those in m, consuming m. On error d is
// left unchanged.
func (d *Data) SetState(m *state.Map) error {
	dec := state.NewDecoder(m, "WebSocketData")
	var n Data
	if v := dec.Any("messages"); dec.Err() == nil {
		msgs, err := state.ListOf(v, messageFromState)
		if err != nil {
			dec.Fail(fmt.Errorf("field %q: %w", "messages", err))
		}
		n.Messages = msgs
	}
	n.ClosedByClient = dec.OptBool("closed_by_client")
	if code := dec.OptInt("close_code"); code != nil {
		c := int(*code)
		n.CloseCode = &c
	}
	n.CloseReason = dec.OptString("close_reason")
	n.TimestampEnd = dec.OptFloat("timestamp_end")
	if err := dec.Finish(); err != nil {
		return err
	}
	*d = n
	return nil
}

// DataFromState returns a new Data built from m, consuming m.
func DataFromState(m *state.Map) (*Data, error) {
	d := &Data{}
	if err := d.SetState(m); err != nil {
		return nil, err
	}
	return d, nil
}

// Clone returns a deep copy of d.
func (d *Data) Clone() *Data {
	out := &Data{}
	if d.Messages != nil {
		out.Messages = make([]*Message, len(d.Messages))
		for i, m := range d.Messages {
			out.Messages[i] = m.Clone()
		}
	}
	out.ClosedByClient = clonePtr(d.ClosedByClient)
	out.CloseCode = clonePtr(d.CloseCode)
	out.CloseReason = clonePtr(d.CloseReason)
	out.TimestampEnd = clonePtr(d.TimestampEnd)
	return out
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
