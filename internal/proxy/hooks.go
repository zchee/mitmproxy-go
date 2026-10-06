// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package proxy drives protocol layers and owns their connections.
package proxy

import (
	"context"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// HookRunner implements [layer.Hooks] for one connection. Manager must be
// non-nil. The callbacks, when set, must be safe for concurrent stream calls.
type HookRunner struct {
	// Manager is the shared addon dispatch domain.
	Manager *addon.Manager
	// Disarm increments this connection's watchdog hold count before lock wait.
	Disarm func()
	// Rearm decrements the hold count after dispatch and interception finish.
	Rearm func()
}

var _ layer.Hooks = (*HookRunner)(nil)

// Fire dispatches hook and waits for its flow to resume; see [layer.Hooks].
func (r *HookRunner) Fire(ctx context.Context, hook addon.Hook) (*layer.Snapshot, error) {
	return r.FireFunc(ctx, nil, hook)
}

// FireFunc atomically prepares and dispatches hook; see [layer.Hooks].
func (r *HookRunner) FireFunc(ctx context.Context, prepare func(context.Context) error, hook addon.Hook) (*layer.Snapshot, error) {
	if r.Disarm != nil {
		r.Disarm()
	}
	if r.Rearm != nil {
		defer r.Rearm()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f := addon.HookFlow(hook)
	var snapshot *layer.Snapshot
	intercepted := false
	finish := func(context.Context) {
		if f != nil {
			intercepted = f.Common().Intercepted()
			if !intercepted {
				snapshot = capture(f)
			}
		}
	}
	if err := r.Manager.HookFunc(ctx, prepare, hook, finish); err != nil {
		return nil, err
	}
	for intercepted {
		if err := f.Common().WaitForResume(ctx); err != nil {
			return nil, err
		}
		// Another writer can intercept again before this hold is acquired.
		if err := r.Manager.Do(ctx, func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			finish(ctx)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return snapshot, nil
}

func capture(f flow.Flow) *layer.Snapshot {
	b := f.Common()
	s := &layer.Snapshot{Live: b.Live}
	if b.Error != nil {
		e := *b.Error
		s.Error = &e
	}
	if b.ClientConn != nil {
		s.Client = b.ClientConn.Clone()
	}
	if b.ServerConn != nil {
		s.Server = b.ServerConn.Clone()
	}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		if f.Request != nil {
			s.Request = f.Request.Clone()
		}
		if f.Response != nil {
			s.Response = f.Response.Clone()
		}
		if f.WebSocket != nil {
			s.NumMessages = len(f.WebSocket.Messages)
			latest := *f.WebSocket
			latest.Messages = nil
			if n := len(f.WebSocket.Messages); n > 0 && f.WebSocket.Messages[n-1] != nil {
				latest.Messages = f.WebSocket.Messages[n-1:]
			}
			s.WebSocket = latest.Clone()
		}
	case *flow.UDPFlow:
		s.NumMessages = len(f.Messages)
		if n := len(f.Messages); n > 0 && f.Messages[n-1] != nil {
			s.LastUDPMessage = f.Messages[n-1].Clone()
		}
	case *flow.TCPFlow:
		s.NumMessages = len(f.Messages)
		if n := len(f.Messages); n > 0 && f.Messages[n-1] != nil {
			s.LastMessage = f.Messages[n-1].Clone()
		}
	}
	return s
}
