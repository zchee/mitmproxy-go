// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package master ties the option, command and addon registries together
// and runs the proxy's lifecycle (mitmproxy's Master).
package master

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

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

	// OnDispatchStart and OnDispatchEnd observe every process-level dispatch
	// lock acquisition and release; see [addon.Config]. They must not manage
	// a connection's idle watchdog, which the proxy's hook runner disarms.
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
	exitErr      atomic.Pointer[error]
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

// Run checks startup errors, sets up servers outside dispatch, fires running,
// checks startup errors again and finishes error collection, then waits for ctx
// or Shutdown. The named "errorcheck" and "proxyserver" addons may implement
// ErrorCheck and ServerSetup respectively; either addon may be absent.
//
// The done hook runs whenever running was invoked, even if it failed. Run
// always closes the master, including on a pre-running startup failure, and
// returns the first startup, running, done or Close error. When Run stops
// because [Master.ShutdownWithError] recorded an error, it returns that
// error, wrapped in an [*ExitError] when it is not one already. Run must be
// called outside dispatch and at most once per Master.
func (m *Master) Run(ctx context.Context) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if cerr := m.Close(context.WithoutCancel(ctx)); err == nil {
			err = cerr
		}
	}()

	ec, _ := m.Addons.Get("errorcheck").(ErrorCheck)
	if ec != nil {
		if err := ec.ShutdownIfErrored(ctx); err != nil {
			return err
		}
	}
	if ps, ok := m.Addons.Get("proxyserver").(ServerSetup); ok {
		setup := make(chan error, 1)
		go func() { setup <- ps.SetupServers(ctx) }()
		select {
		case err = <-setup:
			if err != nil {
				return err
			}
		case <-ctx.Done():
			cancel()
			<-setup
			return m.shutdownResult()
		case <-m.shutdown:
			cancel()
			<-setup
			return m.shutdownResult()
		}
		if ec != nil {
			if err := ec.ShutdownIfErrored(ctx); err != nil {
				return err
			}
		}
	}
	select {
	case <-ctx.Done():
		return m.shutdownResult()
	case <-m.shutdown:
		return m.shutdownResult()
	default:
	}

	// The done hook and the final log delivery must happen even though ctx
	// may be cancelled. Install this before running, which may fail.
	defer func() {
		if derr := m.Addons.Trigger(context.WithoutCancel(ctx), addon.DoneHook{}); err == nil {
			err = derr
		}
	}()
	if err := m.Addons.Trigger(ctx, addon.RunningHook{}); err != nil {
		return err
	}
	if ec != nil {
		if err := ec.ShutdownIfErrored(ctx); err != nil {
			return err
		}
		if err := ec.Finish(ctx); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
	case <-m.shutdown:
	}
	return m.shutdownResult()
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
// any number of times. It never replaces an error recorded by
// [Master.ShutdownWithError].
func (m *Master) Shutdown() {
	m.shutdownOnce.Do(func() { close(m.shutdown) })
}

// ShutdownWithError asks [Master.Run] to stop and return err, the way a
// fatal addon failure such as a stream-file write error must end the
// process with exit status 1 instead of os.Exit. The first non-nil error
// wins: later calls and [Master.Shutdown] never replace it. Run wraps the
// recorded error in an [*ExitError] when it is not one already. A nil err
// behaves as Shutdown. It may be called from any goroutine, any number of
// times.
func (m *Master) ShutdownWithError(err error) {
	if err != nil {
		m.exitErr.CompareAndSwap(nil, &err)
	}
	m.Shutdown()
}

// shutdownResult returns the error recorded by ShutdownWithError, wrapped
// in an [*ExitError] when it is not one already, or nil.
func (m *Master) shutdownResult() error {
	p := m.exitErr.Load()
	if p == nil {
		return nil
	}
	err := *p
	if _, ok := errors.AsType[*ExitError](err); ok {
		return err
	}
	return &ExitError{Err: err}
}
