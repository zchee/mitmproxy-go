// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package master

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/eventsequence"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

// LoadFlow feeds a recorded flow through its lifecycle hooks and their update
// hooks. A single reverse proxy mode retargets HTTP requests to its destination.
// Call it outside dispatch so flow handlers may use addon.Concurrent. Loading
// mutates the flow as eventsequence.Iterate does; each mutation and read of the
// iterator happens under dispatch, but each hook takes its own outermost hold.
// Cancellation or a hook dispatch error stops loading and is returned.
func (m *Master) LoadFlow(ctx context.Context, f flow.Flow) error {
	if err := m.Do(ctx, func(context.Context) error {
		modes := m.Options.Seq("mode")
		hf, ok := f.(*flow.HTTPFlow)
		if !ok || len(modes) != 1 || !strings.HasPrefix(modes[0], "reverse:") {
			return nil
		}
		mode, err := modespec.Parse(modes[0])
		if err != nil {
			return err
		}
		reverse := mode.(modespec.ReverseMode)
		if hf.Request == nil {
			return fmt.Errorf("master: cannot retarget an HTTP flow without a request")
		}
		// Keep upstream's setter order: host and port update the Host header
		// using the old scheme, before the scheme itself changes.
		hf.Request.SetHost(reverse.Address.Host)
		hf.Request.SetPort(reverse.Address.Port)
		hf.Request.Scheme = reverse.Scheme
		return nil
	}); err != nil {
		return err
	}

	next, stop := iter.Pull(eventsequence.Iterate(f))
	defer stop()
	for {
		var hook addon.Hook
		var ok bool
		if err := m.Do(ctx, func(context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			hook, ok = next()
			return nil
		}); err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if err := m.Addons.Hook(ctx, hook); err != nil {
			return err
		}
	}
}
