// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package keepserving shuts the proxy down once playback and file reads
// finish, porting mitmproxy's KeepServing.
package keepserving

import (
	"context"
	"errors"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// DefaultInterval is how often the watcher polls the playback and loading
// state, matching upstream's 0.1 second sleep.
const DefaultInterval = 100 * time.Millisecond

// Config configures a [KeepServing].
type Config struct {
	// Interval is the polling period of the watcher. Zero means
	// [DefaultInterval].
	Interval time.Duration
}

// KeepServing watches the readfile and replay addons once the proxy is
// running and calls the master's Shutdown when none of them has work left,
// unless the keepserving option asks to continue serving. The replay addons
// and their options may be absent: an unregistered option or command counts
// as having no work. Its fields are only accessed under the dispatch lock.
type KeepServing struct {
	master   *master.Master
	interval time.Duration

	cancel context.CancelFunc
	done   chan struct{}
}

// New returns a serving watchdog for m.
func New(m *master.Master, cfg Config) *KeepServing {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	return &KeepServing{master: m, interval: cfg.Interval}
}

// Name identifies the addon, as upstream's keepserving does.
func (*KeepServing) Name() string { return "keepserving" }

// Load registers the keepserving option.
func (k *KeepServing) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "keepserving", options.TypeBool, false, "Continue serving after client playback, server playback or file read. This option is ignored by interactive tools, which always keep serving.")
}

// Keepgoing reports whether a file read, a replay or an active proxy
// connection still has work, by calling the readfile.reading,
// replay.client.count, replay.server.count and
// proxyserver.active_connections commands. A command whose addon is not
// loaded counts as idle. Call it outside dispatch or with a hook's context.
func (k *KeepServing) Keepgoing(ctx context.Context) bool {
	for _, name := range []string{"readfile.reading", "replay.client.count", "replay.server.count", "proxyserver.active_connections"} {
		value, err := k.master.Call(ctx, name)
		if errors.Is(err, command.ErrUnknownCommand) {
			continue
		}
		if err != nil {
			continue
		}
		switch v := value.(type) {
		case bool:
			if v {
				return true
			}
		case int:
			if v != 0 {
				return true
			}
		}
	}
	return false
}

// Running starts the watcher when client playback, server playback or a
// flow file read is configured and the keepserving option is false. Options
// the loaded addons did not register count as unconfigured. The watcher
// runs outside dispatch until the done hook joins it.
func (k *KeepServing) Running(ctx context.Context) error {
	if !k.configured() || k.master.Options.Bool("keepserving") {
		return nil
	}
	// The watcher must not inherit the hook's dispatch frame, which goes
	// stale when this hook chain releases the lock, nor its cancellation,
	// which ends with the hook. A synchronous dispatch cannot release the
	// lock, so the watcher starts from a fresh context there.
	base := context.Background()
	if next, err := addon.Concurrent(ctx, func(clean context.Context) error {
		base = context.WithoutCancel(clean)
		return nil
	}); err == nil {
		ctx = next
	}
	_ = ctx
	watchCtx, cancel := context.WithCancel(base)
	if k.cancel != nil {
		k.cancel()
	}
	k.cancel = cancel
	done := make(chan struct{})
	k.done = done
	go k.watch(watchCtx, done)
	return nil
}

// Done stops the watcher and joins it with the dispatch lock released. A
// done fired synchronously by an addon removal cannot release the lock and
// leaves the cancelled watcher to finish on its own.
func (k *KeepServing) Done(ctx context.Context) error {
	cancel, done := k.cancel, k.done
	k.cancel = nil
	if cancel == nil {
		return nil
	}
	cancel()
	if _, err := addon.Concurrent(ctx, func(context.Context) error {
		<-done
		return nil
	}); err != nil && !errors.Is(err, addon.ErrSyncContext) {
		return err
	}
	return nil
}

func (k *KeepServing) configured() bool {
	for _, name := range []string{"client_replay", "server_replay", "rfile"} {
		opt, ok := k.master.Options.Lookup(name)
		if !ok {
			continue
		}
		switch v := opt.Current().(type) {
		case []string:
			if len(v) > 0 {
				return true
			}
		case *string:
			if v != nil && *v != "" {
				return true
			}
		case string:
			if v != "" {
				return true
			}
		}
	}
	return false
}

func (k *KeepServing) watch(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(k.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !k.Keepgoing(ctx) {
			k.master.Shutdown()
			return
		}
	}
}
