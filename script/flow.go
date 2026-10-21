// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
)

type flowValue struct {
	*object
	i *invocation
	f flow.Flow
}

// Common flow fields map directly to their native scalar types. Optional native
// pointers are None; metadata is an ordered mapping; protocol fields use explicit
// wrappers. Each getter/setter requires the current live invocation frame.
func wrapFlow(i *invocation, f flow.Flow) starlark.Value {
	if f == nil {
		return starlark.None
	}
	v := &flowValue{i: i, f: f}
	v.object = &object{kind: "flow", check: i.modelCheck, names: []string{
		"id", "type", "live", "intercepted", "error", "metadata", "comment", "marked", "is_replay", "timestamp_created",
		"client_conn", "server_conn", "request", "response", "websocket", "messages", "copy", "backup", "revert", "intercept", "resume", "kill", "killable", "modified",
	}, get: v.get, set: v.set}
	return v
}

func (v *flowValue) get(name string) (starlark.Value, error) {
	b := v.f.Common()
	switch name {
	case "id":
		return starlark.String(b.ID), nil
	case "type":
		return starlark.String(v.f.Type()), nil
	case "live":
		return starlark.Bool(b.Live), nil
	case "intercepted":
		return starlark.Bool(b.Intercepted()), nil
	case "error":
		return wrapError(v.i, b.Error), nil
	case "metadata":
		return &stateMapping{i: v.i, m: b.Metadata}, nil
	case "comment":
		return starlark.String(b.Comment), nil
	case "marked":
		return starlark.String(b.Marked), nil
	case "is_replay":
		return optionalString(b.IsReplay), nil
	case "timestamp_created":
		return starlark.Float(b.TimestampCreated), nil
	case "client_conn":
		return wrapClient(v.i, b.ClientConn), nil
	case "server_conn":
		return wrapServer(v.i, b.ServerConn), nil
	case "copy":
		return builtin("flow.copy", v.i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("flow.copy", args, kwargs); err != nil {
				return nil, err
			}
			return wrapFlow(v.i, v.f.Copy()), nil
		}), nil
	case "backup":
		return actionBuiltin("flow.backup", v.i, func() error { v.f.Backup(); return nil }), nil
	case "revert":
		return actionBuiltin("flow.revert", v.i, v.f.Revert), nil
	case "intercept":
		return actionBuiltin("flow.intercept", v.i, func() error { b.Intercept(); return nil }), nil
	case "resume":
		return actionBuiltin("flow.resume", v.i, func() error { b.Resume(); return nil }), nil
	case "kill":
		return actionBuiltin("flow.kill", v.i, b.Kill), nil
	case "killable":
		return builtin("flow.killable", v.i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("flow.killable", args, kwargs); err != nil {
				return nil, err
			}
			return starlark.Bool(b.Killable()), nil
		}), nil
	case "modified":
		return builtin("flow.modified", v.i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("flow.modified", args, kwargs); err != nil {
				return nil, err
			}
			return starlark.Bool(v.f.Modified()), nil
		}), nil
	}
	switch f := v.f.(type) {
	case *flow.HTTPFlow:
		switch name {
		case "request":
			return wrapRequest(v.i, f.Request), nil
		case "response":
			return wrapResponse(v.i, f.Response), nil
		case "websocket":
			return wrapWebSocket(v.i, f.WebSocket), nil
		}
	case *flow.TCPFlow:
		if name == "messages" {
			return tcpMessages(v.i, f), nil
		}
	case *flow.UDPFlow:
		if name == "messages" {
			return udpMessages(v.i, f), nil
		}
	case *flow.DNSFlow:
		switch name {
		case "request":
			return wrapDNS(v.i, f.Request), nil
		case "response":
			return wrapDNS(v.i, f.Response), nil
		}
	}
	return nil, nil
}

func (v *flowValue) set(name string, value starlark.Value) error {
	b := v.f.Common()
	switch name {
	case "comment", "marked":
		x, err := stringValue(value)
		if err != nil {
			return err
		}
		if name == "comment" {
			b.Comment = x
		} else {
			b.Marked = x
		}
		return nil
	case "is_replay":
		if value == starlark.None {
			b.IsReplay = nil
			return nil
		}
		x, err := stringValue(value)
		if err != nil {
			return err
		}
		b.IsReplay = &x
		return nil
	case "error":
		if value == starlark.None {
			b.Error = nil
			return nil
		}
		x, ok := value.(*errorValue)
		if !ok {
			return errors.New("flow.error requires an Error or None")
		}
		if err := x.i.modelCheck(); err != nil {
			return err
		}
		copy := *x.err
		b.Error = &copy
		return nil
	case "metadata":
		x, err := new(conversion).native(value, 0)
		if err != nil {
			return err
		}
		m, ok := x.(*state.Map)
		if !ok {
			return errors.New("metadata requires a string-keyed dict")
		}
		b.Metadata = m
		return nil
	}
	switch f := v.f.(type) {
	case *flow.HTTPFlow:
		switch name {
		case "request":
			x, ok := value.(*requestValue)
			if !ok {
				return errors.New("request requires an HTTP request")
			}
			if err := x.i.modelCheck(); err != nil {
				return err
			}
			f.Request = x.request.Clone()
			return nil
		case "response":
			if value == starlark.None {
				f.Response = nil
				return nil
			}
			x, ok := value.(*responseValue)
			if !ok {
				return errors.New("response requires an HTTP response or None")
			}
			if err := x.i.modelCheck(); err != nil {
				return err
			}
			f.Response = x.response.Clone()
			return nil
		}
	case *flow.DNSFlow:
		if name == "request" || name == "response" {
			if value == starlark.None && name == "response" {
				f.Response = nil
				return nil
			}
			x, ok := value.(*dnsValue)
			if !ok {
				return errors.New("DNS message required")
			}
			if err := x.i.modelCheck(); err != nil {
				return err
			}
			if name == "request" {
				f.Request = x.message.Clone()
			} else {
				f.Response = x.message.Clone()
			}
			return nil
		}
	}
	return fmt.Errorf("flow.%s is read-only or unsupported", name)
}

type errorValue struct {
	*object
	i   *invocation
	err *flow.Error
}

func wrapError(i *invocation, e *flow.Error) starlark.Value {
	if e == nil {
		return starlark.None
	}
	v := &errorValue{i: i, err: e}
	v.object = &object{kind: "error", check: i.modelCheck, names: []string{"msg", "timestamp"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "msg":
			return starlark.String(e.Msg), nil
		case "timestamp":
			return starlark.Float(e.Timestamp), nil
		}
		return nil, nil
	}, set: func(name string, value starlark.Value) error {
		if name != "msg" {
			return fmt.Errorf("error.%s is read-only", name)
		}
		s, err := stringValue(value)
		if err == nil {
			e.Msg = s
		}
		return err
	}}
	return v
}

type stateMapping struct {
	i *invocation
	m *state.Map
}

func (*stateMapping) String() string         { return "<metadata>" }
func (*stateMapping) Type() string           { return "metadata" }
func (*stateMapping) Freeze()                {}
func (m *stateMapping) Truth() starlark.Bool { return m.Len() != 0 }
func (*stateMapping) Hash() (uint32, error)  { return 0, errors.New("unhashable: metadata") }
func (m *stateMapping) Len() int {
	if m.i.modelCheck() != nil || m.m == nil {
		return 0
	}
	return m.m.Len()
}

func (m *stateMapping) Get(key starlark.Value) (starlark.Value, bool, error) {
	if err := m.i.modelCheck(); err != nil {
		return nil, false, err
	}
	name, err := stringValue(key)
	if err != nil {
		return nil, false, err
	}
	if m.m == nil {
		return starlark.None, false, nil
	}
	x, ok := m.m.Get(name)
	if !ok {
		return starlark.None, false, nil
	}
	v, err := new(conversion).value(m.i, x, 0)
	return v, true, err
}

func (m *stateMapping) SetKey(key, value starlark.Value) error {
	if err := m.i.modelCheck(); err != nil {
		return err
	}
	name, err := stringValue(key)
	if err != nil {
		return err
	}
	x, err := new(conversion).native(value, 0)
	if err != nil {
		return err
	}
	if m.m == nil {
		return errors.New("metadata mapping is unavailable")
	}
	m.m.Set(name, x)
	return nil
}

func (m *stateMapping) Iterate() starlark.Iterator {
	values := make([]starlark.Value, 0, m.Len())
	if m.i.modelCheck() == nil && m.m != nil {
		for _, name := range m.m.Keys() {
			values = append(values, starlark.String(name))
		}
	}
	return starlark.NewList(values).Iterate()
}
