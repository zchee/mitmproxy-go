// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package tcp holds the message type of TCP flows.
//
// TCP is stream based, so the proxy chunks the stream into messages for
// practical purposes; do not rely on message boundaries. The flow type itself lives in the flow package. A message
// serialises as upstream's (from_client, content, timestamp) tuple.
package tcp

import (
	"fmt"
	"slices"

	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
)

// Message is one chunk of a TCP stream.
type Message struct {
	// FromClient reports whether the client sent the message.
	FromClient bool
	// Content is the message payload.
	Content []byte
	// Timestamp is when the message was received or created.
	Timestamp float64
}

// NewMessage returns a message created now.
func NewMessage(fromClient bool, content []byte) *Message {
	return &Message{FromClient: fromClient, Content: content, Timestamp: stateutil.Now()}
}

// String formats m as an arrow for the direction ("->" from the client,
// "<-" from the server) followed by the content as a Go-quoted string.
// Upstream prints a Python bytes literal in the same place.
func (m *Message) String() string {
	dir := "<-"
	if m.FromClient {
		dir = "->"
	}
	return fmt.Sprintf("%s %q", dir, m.Content)
}

// GetState returns the message as a (from_client, content, timestamp)
// state tuple.
func (m *Message) GetState() []any {
	return []any{m.FromClient, stateutil.Bytes(m.Content), m.Timestamp}
}

// SetState replaces m's fields from a state tuple. On error m is left
// unchanged.
func (m *Message) SetState(v any) error {
	n, err := MessageFromState(v)
	if err != nil {
		return err
	}
	*m = *n
	return nil
}

// MessageFromState returns a new Message built from a state tuple.
func MessageFromState(v any) (*Message, error) {
	t, err := state.Tuple(v, 3)
	if err != nil {
		return nil, fmt.Errorf("TCPMessage.set_state: %w", err)
	}
	fromClient, err := state.AsBool(t[0])
	if err != nil {
		return nil, fmt.Errorf("TCPMessage.set_state: from_client: %w", err)
	}
	content, err := state.AsBytes(t[1])
	if err != nil {
		return nil, fmt.Errorf("TCPMessage.set_state: content: %w", err)
	}
	ts, err := state.AsFloat(t[2])
	if err != nil {
		return nil, fmt.Errorf("TCPMessage.set_state: timestamp: %w", err)
	}
	return &Message{FromClient: fromClient, Content: content, Timestamp: ts}, nil
}

// Clone returns a deep copy of m.
func (m *Message) Clone() *Message {
	out := *m
	out.Content = slices.Clone(m.Content)
	return &out
}
