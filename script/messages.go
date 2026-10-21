// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"
	"slices"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

type messageSequence struct {
	i           *invocation
	length      func() int
	at          func(int) starlark.Value
	appendValue func(starlark.Value) error
}

func (*messageSequence) String() string         { return "<messages>" }
func (*messageSequence) Type() string           { return "messages" }
func (*messageSequence) Freeze()                {}
func (s *messageSequence) Truth() starlark.Bool { return s.Len() > 0 }
func (*messageSequence) Hash() (uint32, error)  { return 0, errors.New("unhashable: messages") }
func (s *messageSequence) Len() int {
	if s.i.modelCheck() != nil {
		return 0
	}
	return s.length()
}
func (s *messageSequence) Index(n int) starlark.Value { return s.at(n) }
func (s *messageSequence) Iterate() starlark.Iterator {
	values := make([]starlark.Value, s.Len())
	for n := range values {
		values[n] = s.at(n)
	}
	return starlark.NewList(values).Iterate()
}
func (*messageSequence) AttrNames() []string { return []string{"append"} }
func (s *messageSequence) Attr(name string) (starlark.Value, error) {
	if err := s.i.modelCheck(); err != nil {
		return nil, err
	}
	if name != "append" {
		return nil, nil
	}
	return builtin("messages.append", s.i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var value starlark.Value
		if err := starlark.UnpackArgs("messages.append", args, kwargs, "message", &value); err != nil {
			return nil, err
		}
		if s.Len() >= conversionLimit {
			return nil, errors.New("message sequence is full")
		}
		return starlark.None, s.appendValue(value)
	}), nil
}

type messageValue struct {
	*object
	i      *invocation
	native any
}

func wrapMessage(i *invocation, native any) starlark.Value {
	var content *[]byte
	var from *bool
	var timestamp *float64
	var ws *websocket.Message
	switch m := native.(type) {
	case *tcp.Message:
		content, from, timestamp = &m.Content, &m.FromClient, &m.Timestamp
	case *udp.Message:
		content, from, timestamp = &m.Content, &m.FromClient, &m.Timestamp
	case *websocket.Message:
		content, from, timestamp, ws = &m.Content, &m.FromClient, &m.Timestamp, m
	}
	v := &messageValue{i: i, native: native}
	v.object = &object{kind: "message", check: i.modelCheck, names: []string{"content", "from_client", "timestamp", "type", "dropped", "injected", "drop", "copy"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "content":
			return starlark.Bytes(*content), nil
		case "from_client":
			return starlark.Bool(*from), nil
		case "timestamp":
			return starlark.Float(*timestamp), nil
		case "copy":
			return builtin("message.copy", i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				if err := starlark.UnpackArgs("message.copy", args, kwargs); err != nil {
					return nil, err
				}
				switch m := native.(type) {
				case *tcp.Message:
					x := *m
					x.Content = slices.Clone(m.Content)
					return wrapMessage(i, &x), nil
				case *udp.Message:
					x := *m
					x.Content = slices.Clone(m.Content)
					return wrapMessage(i, &x), nil
				case *websocket.Message:
					x := *m
					x.Content = slices.Clone(m.Content)
					return wrapMessage(i, &x), nil
				}
				return nil, errors.New("unknown message type")
			}), nil
		}
		if ws != nil {
			switch name {
			case "type":
				return starlark.MakeInt(int(ws.Type)), nil
			case "dropped":
				return starlark.Bool(ws.Dropped), nil
			case "injected":
				return starlark.Bool(ws.Injected), nil
			case "drop":
				return actionBuiltin("message.drop", i, func() error { ws.Dropped = true; return nil }), nil
			}
		}
		return nil, nil
	}, set: func(name string, value starlark.Value) error {
		switch name {
		case "content":
			b, err := bytesValue(value)
			if err == nil {
				*content = b
			}
			return err
		case "from_client":
			b, err := boolValue(value)
			if err == nil {
				*from = b
			}
			return err
		case "dropped":
			if ws != nil {
				b, err := boolValue(value)
				if err == nil {
					ws.Dropped = b
				}
				return err
			}
		}
		return fmt.Errorf("message.%s is read-only", name)
	}}
	return v
}

func tcpMessages(i *invocation, f *flow.TCPFlow) starlark.Value {
	return &messageSequence{i: i, length: func() int { return len(f.Messages) }, at: func(n int) starlark.Value { return wrapMessage(i, f.Messages[n]) }, appendValue: func(v starlark.Value) error {
		x, ok := v.(*messageValue)
		if !ok {
			return errors.New("TCP message required")
		}
		if err := x.i.modelCheck(); err != nil {
			return err
		}
		m, ok := x.native.(*tcp.Message)
		if !ok {
			return errors.New("TCP message required")
		}
		copy := *m
		copy.Content = slices.Clone(m.Content)
		f.Messages = append(f.Messages, &copy)
		return nil
	}}
}

func udpMessages(i *invocation, f *flow.UDPFlow) starlark.Value {
	return &messageSequence{i: i, length: func() int { return len(f.Messages) }, at: func(n int) starlark.Value { return wrapMessage(i, f.Messages[n]) }, appendValue: func(v starlark.Value) error {
		x, ok := v.(*messageValue)
		if !ok {
			return errors.New("UDP message required")
		}
		if err := x.i.modelCheck(); err != nil {
			return err
		}
		m, ok := x.native.(*udp.Message)
		if !ok {
			return errors.New("UDP message required")
		}
		copy := *m
		copy.Content = slices.Clone(m.Content)
		f.Messages = append(f.Messages, &copy)
		return nil
	}}
}

func wrapWebSocket(i *invocation, data *websocket.Data) starlark.Value {
	if data == nil {
		return starlark.None
	}
	return &object{kind: "websocket", check: i.modelCheck, names: []string{"messages", "closed_by_client", "close_code", "close_reason", "timestamp_end"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "messages":
			return &messageSequence{i: i, length: func() int { return len(data.Messages) }, at: func(n int) starlark.Value { return wrapMessage(i, data.Messages[n]) }, appendValue: func(v starlark.Value) error {
				x, ok := v.(*messageValue)
				if !ok {
					return errors.New("WebSocket message required")
				}
				if err := x.i.modelCheck(); err != nil {
					return err
				}
				m, ok := x.native.(*websocket.Message)
				if !ok {
					return errors.New("WebSocket message required")
				}
				copy := *m
				copy.Content = slices.Clone(m.Content)
				data.Messages = append(data.Messages, &copy)
				return nil
			}}, nil
		case "closed_by_client":
			if data.ClosedByClient == nil {
				return starlark.None, nil
			}
			return starlark.Bool(*data.ClosedByClient), nil
		case "close_code":
			if data.CloseCode == nil {
				return starlark.None, nil
			}
			return starlark.MakeInt(*data.CloseCode), nil
		case "close_reason":
			return optionalString(data.CloseReason), nil
		case "timestamp_end":
			return optionalFloat(data.TimestampEnd), nil
		}
		return nil, nil
	}, set: func(name string, value starlark.Value) error {
		switch name {
		case "closed_by_client":
			if value == starlark.None {
				data.ClosedByClient = nil
				return nil
			}
			x, err := boolValue(value)
			if err == nil {
				data.ClosedByClient = &x
			}
			return err
		case "close_code":
			if value == starlark.None {
				data.CloseCode = nil
				return nil
			}
			x, err := intValue(value)
			if err == nil {
				data.CloseCode = &x
			}
			return err
		case "close_reason":
			if value == starlark.None {
				data.CloseReason = nil
				return nil
			}
			x, err := stringValue(value)
			if err == nil {
				data.CloseReason = &x
			}
			return err
		}
		return fmt.Errorf("websocket.%s is read-only", name)
	}}
}
