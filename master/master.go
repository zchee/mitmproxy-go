// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package master ties the option, command and addon registries together
// and runs the proxy's lifecycle (mitmproxy's Master).
package master

import (
	"context"
	"log/slog"
	"sync"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

// Config configures a [Master].
type Config struct {
	// Options is the option registry. Nil means [options.New], the core
	// options.
	Options *options.Manager

	// Logger receives the addon manager's records: handler errors and
	// warnings. Nil means [slog.Default] at the time of each record.
	Logger *slog.Logger

	// LogQueueSize bounds the entries waiting for the add_log hook; see
	// [addon.LogHandlerOptions].
	LogQueueSize int

	// OnDispatchStart and OnDispatchEnd are passed to the addon manager;
	// see [addon.Config].
	OnDispatchStart func()
	OnDispatchEnd   func()
}

// Master owns the registries addons share and runs the hooks that start
// and stop them.
type Master struct {
	// Options holds the options.
	Options *options.Manager
	// Commands holds the commands.
	Commands *command.Manager
	// Addons holds the addons and dispatches hooks to them.
	Addons *addon.Manager

	logs *addon.LogHandler

	shutdownOnce sync.Once
	shutdown     chan struct{}
}

// New returns a Master with no addons.
func New(cfg Config) *Master {
	opts := cfg.Options
	if opts == nil {
		opts = options.New()
	}
	m := &Master{
		Options:  opts,
		Commands: command.NewManager(),
		shutdown: make(chan struct{}),
	}
	m.Addons = addon.NewManager(m.Options, m.Commands, addon.Config{
		Logger:          cfg.Logger,
		OnDispatchStart: cfg.OnDispatchStart,
		OnDispatchEnd:   cfg.OnDispatchEnd,
	})
	m.logs = addon.NewLogHandler(func(ctx context.Context, e addon.LogEntry) {
		// Trigger recovers handler panics and logs handler errors; it
		// returns an error only for an options error, which add_log
		// handlers have no option change to roll back with.
		_ = m.Addons.Trigger(ctx, addon.AddLogHook{Entry: e})
	}, addon.LogHandlerOptions{QueueSize: cfg.LogQueueSize})
	return m
}

// LogHandler returns the [slog.Handler] that feeds the add_log hook. The
// program combines it with its other log outputs and installs the result as
// the default logger; the master does not change the default logger
// itself.
func (m *Master) LogHandler() *addon.LogHandler { return m.logs }

// Do runs fn under the dispatch lock with a context through which option
// changes, commands and hooks fired inside fn re-enter the lock instead of
// deadlocking. Every goroutine that is not running a hook (frontends,
// script reloaders, timers) must change flows, options and addon state
// only inside Do.
func (m *Master) Do(ctx context.Context, fn func(ctx context.Context) error) error {
	return m.Addons.Do(ctx, fn)
}

// Call runs the command registered under name with args under the
// dispatch lock and returns its result; see [addon.Manager.Call]. It is
// the entry point for frontends and other goroutines outside the hooks,
// and may also be called with the context of a hook.
func (m *Master) Call(ctx context.Context, name string, args ...any) (any, error) {
	return m.Addons.Call(ctx, name, args...)
}

// Run fires the running hook, waits until ctx is done or [Master.Shutdown]
// is called, fires the done hook and then closes the master (see
// [Master.Close]). The done hook runs even when the running hook returned
// an error, as mitmproxy fires done whenever it fired running. Run returns
// the first error of the running hook, the done hook and Close.
func (m *Master) Run(ctx context.Context) error {
	err := m.Addons.Trigger(ctx, addon.RunningHook{})
	if err == nil {
		select {
		case <-ctx.Done():
		case <-m.shutdown:
		}
	}
	// The done hook and the final log delivery must happen even though ctx
	// may be cancelled.
	stopCtx := context.WithoutCancel(ctx)
	if derr := m.Addons.Trigger(stopCtx, addon.DoneHook{}); err == nil {
		err = derr
	}
	if cerr := m.Close(stopCtx); err == nil {
		err = cerr
	}
	return err
}

// Close stops firing configure for option changes, delivers the log
// entries still queued for add_log, and stops the add_log delivery
// goroutine; it waits for that until ctx is done. [Master.Run] calls it; a
// master that is never run must be closed by its owner. Calling Close
// again is allowed.
func (m *Master) Close(ctx context.Context) error {
	m.Addons.Close()
	return m.logs.Close(ctx)
}

// Shutdown asks [Master.Run] to stop. It may be called from any goroutine,
// any number of times.
func (m *Master) Shutdown() {
	m.shutdownOnce.Do(func() { close(m.shutdown) })
}
