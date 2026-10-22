// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"os"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/eventsequence"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
)

func (l *Loader) run(ctx context.Context, flows []flow.Flow, path command.Path) error {
	if l.closed.Load() || l.stopping.Load() {
		return errors.New("script loader is closed")
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
	invoke := func(hook addon.Hook) bool {
		if err := l.master.Addons.InvokeSync(ctx, mod.addon(), hook); err != nil {
			l.logger().ErrorContext(ctx, "Addon error: "+diagnostic(err))
			return false
		}
		return true
	}
	keys := make(map[string]struct{})
	for _, key := range l.master.Options.Keys() {
		keys[key] = struct{}{}
	}
	if !invoke(addon.ConfigureHook{Updated: keys}) || !invoke(addon.RunningHook{}) {
		return nil
	}
	for _, f := range flows {
		for hook := range eventsequence.Iterate(f) {
			if !invoke(hook) {
				return nil
			}
		}
	}
	return nil
}
