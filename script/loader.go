// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package script embeds trusted operator-supplied Starlark addons. Ordinary
// evaluations run inside the master's addon dispatch domain. Source and HTTP
// limits are safety bounds, not a CPU, memory, filesystem or network sandbox.
package script

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// Config supplies frontend-owned capabilities to a script loader.
// The zero value permits scripts but disables outbound HTTP until ListenAddrs
// is supplied; it never silently disables self-proxy protection.
type Config struct {
	// Logger is the master's existing logger. Nil uses slog.Default per call.
	Logger *slog.Logger
	// ListenAddrs returns an owned snapshot of this master's actual listener
	// tuples. Supply proxyserver.ListenAddrs; nil makes ctx.http_get fail closed.
	ListenAddrs func() []connection.Address
}

// Loader is the default scripting addon. Register it with m.Addons.Add.
// Call Close outside dispatch on construction failure, metadata-only exit and
// shutdown, before the master's final log flush. Done retires without joining.
type Loader struct {
	master              *master.Master
	cfg                 Config
	ctx                 context.Context
	cancel              context.CancelFunc
	closed              atomic.Bool
	current             atomic.Pointer[invocation]
	stopping            atomic.Bool
	mu                  sync.Mutex
	wg                  sync.WaitGroup
	watching            bool
	transport           *http.Transport
	client              *http.Client
	entries             []*scriptEntry // dispatch-owned, in option order
	running             bool
	generation          uint64
	configureGeneration uint64
	// Tests replace the ticker source before loading; production always uses
	// the one-second mtime watcher.
	ticks     <-chan time.Time
	onPoll    func()
	sleepWait func(context.Context, time.Duration) error
}

type scriptEntry struct {
	owner      *Loader
	path       string
	fullpath   string
	generation uint64
	mtime      time.Time
	module     *moduleAddon
	retired    bool
	httpSlots  chan struct{}
}

// New returns an unregistered scripting addon bound to m. It starts no watcher,
// listener or HTTP operation. m must be non-nil and owns all shared registries.
func New(m *master.Master, cfg Config) *Loader {
	ctx, cancel := context.WithCancel(context.Background())
	l := &Loader{master: m, cfg: cfg, ctx: ctx, cancel: cancel}
	l.initHTTP()
	return l
}

// Name returns the default addon name.
func (*Loader) Name() string { return "scriptloader" }

// Addons returns loaded scripts in their operator-selected order.
// The addon manager calls it while holding dispatch.
func (l *Loader) Addons() []any {
	out := make([]any, 0, len(l.entries))
	for _, e := range l.entries {
		if e.module != nil {
			out = append(out, e.module.addon())
		}
	}
	return out
}

// Load registers the scripting options with their upstream metadata.
func (l *Loader) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "scripts", options.TypeSeq, []string{}, "Execute a script."); err != nil {
		return err
	}
	return loader.AddOption(ctx, "script_max_steps", options.TypeInt, 0, "Maximum number of Starlark execution steps per script hook call. 0 means no limit.")
}

// Configure synchronously loads new scripts and preserves unchanged instances.
func (l *Loader) Configure(ctx context.Context, updated map[string]struct{}) error {
	if l.master.Options.Int("script_max_steps") < 0 {
		return &options.OptionsError{Msg: "script_max_steps must not be negative"}
	}
	if _, ok := updated["scripts"]; !ok {
		return nil
	}
	if l.closed.Load() || l.stopping.Load() {
		return options.Errorf("script loader is closed")
	}
	paths := l.master.Options.Seq("scripts")
	seen := make(map[string]bool, len(paths))
	fullpaths := make(map[string]string, len(paths))
	for _, path := range paths {
		if seen[path] {
			return &options.OptionsError{Msg: "Duplicate script"}
		}
		seen[path] = true
	}
	for _, path := range paths {
		fullpath, err := sourcePath(path)
		if err != nil {
			return &options.OptionsError{Msg: err.Error()}
		}
		st, err := os.Stat(fullpath)
		if err != nil || !st.Mode().IsRegular() {
			return &options.OptionsError{Msg: "No such script: " + fullpath}
		}
		fullpaths[path] = fullpath
	}
	old := make(map[string]*scriptEntry, len(l.entries))
	for _, e := range l.entries {
		if seen[e.path] {
			old[e.path] = e
			continue
		}
		l.logger().InfoContext(ctx, "Un-loading script: "+e.path)
		if err := l.remove(ctx, e); err != nil {
			return err
		}
	}
	ordered := make([]*scriptEntry, 0, len(paths))
	var added []*scriptEntry
	for _, path := range paths {
		if e := old[path]; e != nil {
			ordered = append(ordered, e)
			continue
		}
		l.generation++
		e := &scriptEntry{owner: l, path: path, fullpath: fullpaths[path], generation: l.generation, httpSlots: make(chan struct{}, 32)}
		ordered = append(ordered, e)
		added = append(added, e)
	}
	l.entries = ordered
	l.configureGeneration++
	// Configure retained modules before initializing additions, preserving the
	// upstream ordering while avoiding a second configure in tree traversal.
	for _, e := range ordered {
		if e.module != nil {
			if err := l.master.Addons.InvokeSync(ctx, e.module.addon(), addon.ConfigureHook{Updated: updated}); err != nil {
				l.loadError(ctx, e, err)
			}
		}
	}
	for _, e := range added {
		src, err := readSource(e.fullpath)
		e.mtime = src.mtime
		if err != nil {
			l.loadError(ctx, e, err)
			continue
		}
		e.mtime = src.mtime
		l.replace(ctx, e, src)
	}
	if len(l.entries) != 0 {
		l.startWatcher()
	}
	return nil
}

// Running records startup; the manager delivers running to the script children.
func (l *Loader) Running(context.Context) error { l.running = true; return nil }

// Done retires the loader without joining while dispatch is held. Close owns
// cancellation after the manager has delivered done to every registered child.
func (l *Loader) Done(context.Context) error { l.stopping.Store(true); return nil }

// Close cancels and joins all owned work and closes idle HTTP connections.
// It is idempotent and must be called outside addon dispatch. No caller may
// register new work after Close begins.
func (l *Loader) Close() error {
	l.mu.Lock()
	l.closed.Store(true)
	l.cancel()
	l.mu.Unlock()
	l.wg.Wait()
	l.transport.CloseIdleConnections()
	return nil
}

func (l *Loader) logger() *slog.Logger {
	if l.cfg.Logger != nil {
		return l.cfg.Logger
	}
	return slog.Default()
}

func (l *Loader) startWatcher() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.watching || l.closed.Load() {
		return
	}
	l.watching = true
	l.wg.Go(l.watch)
}

func (l *Loader) watch() {
	ch := l.ticks
	if ch == nil {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		ch = ticker.C
	}
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ch:
		}
		var entries []*scriptEntry
		if err := l.master.Do(l.ctx, func(context.Context) error { entries = slices.Clone(l.entries); return nil }); err != nil {
			return
		}
		for _, e := range entries {
			// Only immutable path/generation are read here. The observed mtime
			// and membership are checked after reacquiring fresh dispatch.
			src, readErr := readSource(e.fullpath)
			err := l.master.Do(l.ctx, func(ctx context.Context) error {
				if e.retired || l.stopping.Load() || !slices.Contains(l.entries, e) {
					return nil
				}
				if errors.Is(readErr, os.ErrNotExist) {
					paths := l.master.Options.Seq("scripts")
					paths = slices.DeleteFunc(paths, func(p string) bool { return p == e.path })
					return l.master.Options.Update(ctx, map[string]any{"scripts": paths})
				}
				if !src.mtime.After(e.mtime) {
					return nil
				}
				e.mtime = src.mtime
				if readErr != nil {
					l.loadError(ctx, e, readErr)
					return nil
				}
				l.replace(ctx, e, src)
				return nil
			})
			if err != nil {
				if l.ctx.Err() != nil {
					return
				}
				l.logger().Error("script watcher: " + err.Error())
			}
		}
		if l.onPoll != nil {
			l.onPoll()
		}
	}
}

func (l *Loader) remove(ctx context.Context, e *scriptEntry) error {
	e.retired = true
	if e.module == nil {
		return nil
	}
	err := l.master.Addons.Remove(ctx, e.module.addon())
	e.module = nil
	return err
}

func (l *Loader) replace(ctx context.Context, e *scriptEntry, src source) {
	l.logger().InfoContext(ctx, "Loading script "+e.path)
	if e.module != nil {
		if err := l.master.Addons.Remove(ctx, e.module.addon()); err != nil {
			l.loadError(ctx, e, err)
			return
		}
		e.module = nil
	}
	mod, err := l.initialize(ctx, e, src.data)
	if err != nil {
		l.loadError(ctx, e, err)
		return
	}
	if err = l.master.Addons.Register(ctx, mod.addon()); err != nil {
		// Deferred option processing may fail after publishing the addon.
		// Do not remove a different instance that already owned the name.
		if l.master.Addons.Get(mod.Name()) == mod.addon() {
			err = errors.Join(err, l.master.Addons.Remove(ctx, mod.addon()))
		}
		l.loadError(ctx, e, err)
		return
	}
	if err = mod.checkTree(); err != nil {
		if removeErr := l.master.Addons.Remove(ctx, mod.addon()); removeErr != nil {
			err = errors.Join(err, removeErr)
		}
		l.loadError(ctx, e, err)
		return
	}
	e.module = mod
	keys := make(map[string]struct{})
	for _, k := range l.master.Options.Keys() {
		keys[k] = struct{}{}
	}
	if err = l.master.Addons.InvokeSync(ctx, mod.addon(), addon.ConfigureHook{Updated: keys}); err != nil {
		l.loadError(ctx, e, err)
	}
	if l.running {
		if err = l.master.Addons.InvokeSync(ctx, mod.addon(), addon.RunningHook{}); err != nil {
			l.loadError(ctx, e, err)
		}
	}
}

func (l *Loader) loadError(ctx context.Context, e *scriptEntry, err error) {
	l.logger().ErrorContext(ctx, fmt.Sprintf("error in script %s: %s", e.path, diagnostic(err)))
}
