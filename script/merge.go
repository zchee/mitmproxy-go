// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

type mergeSegment struct {
	before, after *state.Map
	action        string
}

type flowMerge struct {
	live, copy     flow.Flow
	baseline       *state.Map
	segments       []mergeSegment
	messageIndices map[string][]int
}

// Copy's serialized state does not include streaming or connection runtime state.
// Restore those only on the detached clone, never by copying a flow's mutex.
func invocationClone(f flow.Flow) (flow.Flow, error) {
	var c flow.Flow
	switch f.(type) {
	case *flow.HTTPFlow:
		c = new(flow.HTTPFlow)
	case *flow.TCPFlow:
		c = new(flow.TCPFlow)
	case *flow.UDPFlow:
		c = new(flow.UDPFlow)
	case *flow.DNSFlow:
		c = new(flow.DNSFlow)
	default:
		return nil, fmt.Errorf("unsupported invocation flow %T", f)
	}
	if err := setInvocationState(c, f); err != nil {
		return nil, err
	}
	c.Common().ID, c.Common().Live = f.Common().ID, f.Common().Live
	c.Common().ClientConn, c.Common().ServerConn = nil, nil
	if f.Common().ClientConn != nil {
		c.Common().ClientConn = f.Common().ClientConn.Clone()
	}
	if f.Common().ServerConn != nil {
		c.Common().ServerConn = f.Common().ServerConn.Clone()
	}
	if h, ok := f.(*flow.HTTPFlow); ok {
		clone := c.(*flow.HTTPFlow)
		if h.Request != nil {
			clone.Request = h.Request.Clone()
		}
		if h.Response != nil {
			clone.Response = h.Response.Clone()
		}
	}
	return c, nil
}

// Decode detached state with temporary required fields, then restore absence
// before publishing the result. The normal decoder preserves private backup and
// interception state without copying the flow's mutex or changing backups.
func setInvocationState(f, source flow.Flow) error {
	snapshot := state.CopyMap(source.GetState())
	d, dnsFlow := source.(*flow.DNSFlow)
	requestless := dnsFlow && d.Request == nil
	if requestless {
		snapshot.Set("request", new(dns.Message).GetState())
	}
	if source.Common().ClientConn == nil {
		snapshot.Set("client_conn", connection.NewClient(connection.Address{}, connection.Address{}, 0).GetState())
	}
	if source.Common().ServerConn == nil {
		snapshot.Set("server_conn", connection.NewServer(nil).GetState())
	}
	if err := f.SetState(snapshot); err != nil {
		return err
	}
	if requestless {
		f.(*flow.DNSFlow).Request = nil
	}
	if source.Common().ClientConn == nil {
		f.Common().ClientConn = nil
	}
	if source.Common().ServerConn == nil {
		f.Common().ServerConn = nil
	}
	return nil
}

func mergeSnapshot(f flow.Flow) *state.Map {
	snapshot := state.CopyMap(f.GetState())
	if h, ok := f.(*flow.HTTPFlow); ok {
		for name, stream := range map[string]bool{"request": h.Request != nil && h.Request.Stream, "response": h.Response != nil && h.Response.Stream} {
			if value, _ := snapshot.Get(name); value != nil {
				value.(*state.Map).Set("stream", stream)
			}
		}
	}
	return snapshot
}

func newFlowMerge(live flow.Flow) (*flowMerge, error) {
	copy, err := invocationClone(live)
	if err != nil {
		return nil, err
	}
	return &flowMerge{live: live, copy: copy, baseline: mergeSnapshot(copy), messageIndices: make(map[string][]int)}, nil
}

func (m *flowMerge) checkpoint(action string) {
	after := mergeSnapshot(m.copy)
	m.segments = append(m.segments, mergeSegment{before: m.baseline, after: after, action: action})
	m.baseline = after
}

func (v *flowValue) action(name string, fn func() error) *starlark.Builtin {
	return actionBuiltin("flow."+name, v.i, func() error {
		merge := v.i.merges[v.f]
		if merge != nil {
			merge.checkpoint(name)
		}
		err := fn()
		if merge != nil {
			if err != nil {
				merge.segments[len(merge.segments)-1].action = ""
			}
			merge.baseline = mergeSnapshot(v.f)
		}
		return err
	})
}

func (m *flowMerge) apply(ctx context.Context, logger *slog.Logger) error {
	base := m.live.Common()
	protected := !base.Killable()
	savedError, savedLive := base.Error, base.Live
	killed := base.Error != nil && base.Error.Msg == flow.KilledMessage
	normalize := func() {
		if protected {
			base.Error, base.Live = savedError, savedLive
		}
		if killed {
			base.Resume()
		}
	}
	var errs []error
	for _, segment := range m.segments {
		if err := m.applySegment(segment, protected); err != nil {
			errs = append(errs, err)
		}
		switch segment.action {
		case "":
		case "backup":
			m.live.Backup()
		case "revert":
			if err := m.live.Revert(); err != nil {
				errs = append(errs, err)
			}
			clear(m.messageIndices)
		case "intercept":
			base.Intercept()
		case "resume":
			base.Resume()
		case "kill":
			if err := base.Kill(); err != nil {
				logger.ErrorContext(ctx, "concurrent flow.kill: "+err.Error())
			} else {
				protected, killed = true, true
				savedError, savedLive = base.Error, base.Live
			}
		default:
			errs = append(errs, fmt.Errorf("unknown flow action %q", segment.action))
		}
		normalize()
	}
	normalize()
	return errors.Join(errs...)
}

func (m *flowMerge) applySegment(segment mergeSegment, protectError bool) error {
	current := mergeSnapshot(m.live)
	for key, after := range segment.after.All() {
		before, _ := segment.before.Get(key)
		if state.Equal(before, after) {
			continue
		}
		switch key {
		case "version", "type", "id", "timestamp_created", "client_conn", "server_conn", "backup", "intercepted":
			continue
		case "error":
			if protectError {
				continue
			}
			if e, ok := after.(*state.Map); ok {
				if msg, _ := e.Get("msg"); msg == flow.KilledMessage {
					continue
				}
			}
		}
		live, _ := current.Get(key)
		merged := m.mergeValue(key, before, after, live)
		if err := applyFlowField(m.live, key, merged); err != nil {
			return fmt.Errorf("merge %s: %w", key, err)
		}
	}
	return nil
}

func (m *flowMerge) mergeValue(path string, before, after, live any) any {
	if state.Equal(before, after) {
		return state.Copy(live)
	}
	a, aok := after.(*state.Map)
	b, bok := before.(*state.Map)
	l, lok := live.(*state.Map)
	if aok && bok && lok && a != nil && b != nil && l != nil {
		out := state.CopyMap(l)
		for key, value := range a.All() {
			old, exists := b.Get(key)
			current, _ := l.Get(key)
			if !exists || !state.Equal(old, value) {
				out.Set(key, m.mergeValue(path+"/"+key, old, value, current))
			}
		}
		for key := range b.All() {
			if !a.Has(key) {
				out.Delete(key)
			}
		}
		return out
	}
	if path == "messages" || path == "websocket/messages" {
		b, bok := before.([]any)
		a, aok := after.([]any)
		l, lok := live.([]any)
		if bok && aok && lok {
			return m.mergeMessages(path, b, a, l)
		}
	}
	return state.Copy(after)
}

func (m *flowMerge) mergeMessages(path string, before, after, live []any) []any {
	out := state.Copy(live).([]any)
	indices := m.messageIndices[path]
	if indices == nil {
		indices = make([]int, len(before))
		for n := range indices {
			indices[n] = n
		}
	}
	for n, value := range after {
		if n >= len(before) {
			indices = append(indices, len(out))
			out = append(out, state.Copy(value))
			continue
		}
		if state.Equal(before[n], value) || n >= len(indices) {
			continue
		}
		index := indices[n]
		if index >= len(out) {
			continue
		}
		// Message tuples have stable original indices and independent semantic
		// fields; an unchanged direction/content/drop flag keeps its live value.
		old, oldOK := before[n].([]any)
		next, nextOK := value.([]any)
		current, currentOK := out[index].([]any)
		if oldOK && nextOK && currentOK && len(old) == len(next) && len(next) == len(current) {
			for field := range next {
				if !state.Equal(old[field], next[field]) {
					current[field] = state.Copy(next[field])
				}
			}
		} else {
			out[index] = state.Copy(value)
		}
	}
	m.messageIndices[path] = indices
	return out
}

func applyFlowField(f flow.Flow, name string, value any) error {
	base := f.Common()
	switch name {
	case "comment":
		base.Comment = value.(string)
		return nil
	case "marked":
		base.Marked = value.(string)
		return nil
	case "metadata":
		base.Metadata = value.(*state.Map)
		return nil
	case "is_replay":
		base.IsReplay = nil
		if value != nil {
			base.IsReplay = new(value.(string))
		}
		return nil
	case "error":
		base.Error = nil
		if value != nil {
			var err error
			base.Error, err = flow.ErrorFromState(value.(*state.Map))
			return err
		}
		return nil
	}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		switch name {
		case "request":
			if value == nil {
				f.Request = nil
				return nil
			}
			data := value.(*state.Map)
			stream, _ := data.Pop("stream")
			r, err := httpmsg.RequestFromState(data)
			if err != nil {
				return err
			}
			if f.Request != nil {
				r.StreamFunc = f.Request.StreamFunc
				*f.Request = *r
			} else {
				f.Request = r
			}
			f.Request.Stream, _ = stream.(bool)
			return nil
		case "response":
			if value == nil {
				f.Response = nil
				return nil
			}
			data := value.(*state.Map)
			stream, _ := data.Pop("stream")
			r, err := httpmsg.ResponseFromState(data)
			if err != nil {
				return err
			}
			if f.Response != nil {
				r.StreamFunc = f.Response.StreamFunc
				*f.Response = *r
			} else {
				f.Response = r
			}
			f.Response.Stream, _ = stream.(bool)
			return nil
		case "websocket":
			if value == nil {
				f.WebSocket = nil
				return nil
			}
			data, err := websocket.DataFromState(value.(*state.Map))
			if err != nil {
				return err
			}
			if f.WebSocket != nil {
				*f.WebSocket = *data
			} else {
				f.WebSocket = data
			}
			return nil
		}
	case *flow.DNSFlow:
		if name == "request" || name == "response" {
			var message *dns.Message
			if value != nil {
				var err error
				message, err = dns.MessageFromState(value.(*state.Map))
				if err != nil {
					return err
				}
			}
			if name == "request" {
				if f.Request != nil && message != nil {
					*f.Request = *message
				} else {
					f.Request = message
				}
			} else {
				if f.Response != nil && message != nil {
					*f.Response = *message
				} else {
					f.Response = message
				}
			}
			return nil
		}
	case *flow.TCPFlow:
		if name == "messages" {
			values := value.([]any)
			messages := make([]*tcp.Message, len(values))
			for n, value := range values {
				var err error
				messages[n], err = tcp.MessageFromState(value)
				if err != nil {
					return err
				}
			}
			for n, message := range messages {
				if n < len(f.Messages) {
					*f.Messages[n] = *message
					messages[n] = f.Messages[n]
				}
			}
			f.Messages = messages
			return nil
		}
	case *flow.UDPFlow:
		if name == "messages" {
			values := value.([]any)
			messages := make([]*udp.Message, len(values))
			for n, value := range values {
				var err error
				messages[n], err = udp.MessageFromState(value)
				if err != nil {
					return err
				}
			}
			for n, message := range messages {
				if n < len(f.Messages) {
					*f.Messages[n] = *message
					messages[n] = f.Messages[n]
				}
			}
			f.Messages = messages
			return nil
		}
	}
	return fmt.Errorf("unsupported flow field %q", name)
}
