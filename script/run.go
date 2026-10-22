// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/eventsequence"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
)

// Every nested run creates a fresh interpreter; its step budget and recursion
// checks cannot bound the native command stack. Keep script composition small.
const maxScriptRunDepth = 16

var errScriptRunDepth = fmt.Errorf("script.run nested call exceeds depth %d", maxScriptRunDepth)

func (l *Loader) run(ctx context.Context, flows []flow.Flow, path command.Path) error {
	if l.closed.Load() || l.stopping.Load() {
		return errors.New("script loader is closed")
	}
	depth := l.syncRunDepth.Add(1)
	defer l.syncRunDepth.Add(-1)
	if depth > maxScriptRunDepth {
		return errScriptRunDepth
	}
	fail := func(err error) error {
		if depth > 1 && errors.Is(err, errScriptRunDepth) {
			return err
		}
		l.logger().ErrorContext(ctx, "Addon error: "+diagnostic(err))
		return nil
	}
	fullpath, err := sourcePath(string(path))
	if err != nil {
		l.logger().ErrorContext(ctx, "No such script: "+string(path))
		return nil
	}
	info, err := os.Stat(fullpath)
	if err != nil || !info.Mode().IsRegular() {
		l.logger().ErrorContext(ctx, "No such script: "+string(path))
		return nil
	}
	e := &scriptEntry{owner: l, path: string(path), fullpath: fullpath, synchronous: true, httpSlots: make(chan struct{}, 32)}
	src, err := readSource(fullpath)
	if err != nil {
		l.loadError(ctx, e, err)
		return nil
	}
	mod, err := l.initialize(ctx, e, src.data)
	if err != nil {
		if errors.Is(err, errScriptRunDepth) {
			return fail(err)
		}
		l.loadError(ctx, e, err)
		return nil
	}
	defer func() { e.retired = true; mod.graph.retired = true }()
	var bindChildren func(*moduleAddon)
	bindChildren = func(m *moduleAddon) {
		m.children = buildChildren(m, m.members)
		m.loaded = true
		for _, child := range m.children {
			bindChildren(child)
		}
	}
	bindChildren(mod)
	keys := make(map[string]struct{})
	for _, key := range l.master.Options.Keys() {
		keys[key] = struct{}{}
	}
	for _, hook := range []addon.Hook{addon.ConfigureHook{Updated: keys}, addon.RunningHook{}} {
		if err := l.master.Addons.InvokeSync(ctx, mod.addon(), hook); err != nil {
			return fail(err)
		}
	}
	for _, f := range flows {
		for hook := range eventsequence.Iterate(f) {
			if err := l.master.Addons.InvokeSync(ctx, mod.addon(), hook); err != nil {
				return fail(err)
			}
		}
	}
	return nil
}
