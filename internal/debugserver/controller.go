// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package debugserver

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/telemetry"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

const addressOption = "pprof_addr"

// Config supplies bounded, nonblocking diagnostics from the containing instance.
type Config struct {
	Counters func() telemetry.Status
	Logger   *slog.Logger
}

// Status distinguishes the requested option from an acknowledged bound listener.
type Status struct {
	Requested string `json:"requested"`
	Address   string `json:"address"`
	Enabled   bool   `json:"enabled"`
	Failed    bool   `json:"failed"`
	Stopped   bool   `json:"stopped"`
}

// Controller owns one private diagnostics listener and its reconciliation worker.
type Controller struct {
	cfg    Config
	master *master.Master

	mu           sync.Mutex
	current      *serverGeneration
	retiring     *serverGeneration
	started      bool
	settling     bool
	requested    string
	settled      string
	settleErr    error
	closeErr     error
	workerCancel context.CancelFunc
	graceCancel  context.CancelFunc
	closeContext context.Context
	closeCancel  context.CancelFunc
	changed      chan struct{}
	wake         chan struct{}
	stop         chan struct{}
	done         chan struct{}
	stopping     atomic.Bool
	closeOnce    sync.Once
}

// New returns an inert controller; it starts no worker or listener.
func New(cfg Config) *Controller {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Controller{cfg: cfg, changed: make(chan struct{}), wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
}

// Bind supplies the Master once, before registering the addon or starting it.
func (c *Controller) Bind(m *master.Master) *Controller {
	c.master = m
	return c
}

// Name identifies the option and lifecycle addon.
func (*Controller) Name() string { return "debugserver" }

// Load registers the disabled-by-default option without binding a socket.
func (c *Controller) Load(ctx context.Context, loader *addon.Loader) error {
	if c.master == nil {
		return errors.New("debugserver: Bind must precede addon registration")
	}
	return loader.AddOption(ctx, addressOption, options.TypeStr, "", "Serve net/http/pprof on this loopback address, for example 127.0.0.1:6060. Empty disables it.")
}

// Configure validates the address and signals reconciliation without I/O.
func (c *Controller) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated[addressOption]; !ok {
		return nil
	}
	if _, err := parseAddress(c.master.Options.Str(addressOption)); err != nil {
		return err
	}
	c.signal()
	return nil
}

func (c *Controller) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Running starts the sole worker; metadata-only construction remains inert.
func (c *Controller) Running(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started || c.stopping.Load() {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.workerCancel = cancel
	c.started = true
	go c.run(ctx)
	c.signal()
	return nil
}

// Done prevents new reconciliation; Close performs acknowledged cleanup.
func (c *Controller) Done(context.Context) error {
	c.stopping.Store(true)
	return nil
}

func (c *Controller) readAddress(ctx context.Context) (string, error) {
	var requested string
	err := c.master.Do(ctx, func(context.Context) error {
		requested = c.master.Options.Str(addressOption)
		return nil
	})
	return requested, err
}

func (c *Controller) run(ctx context.Context) {
	defer close(c.done)
	for {
		select {
		case <-c.stop:
			c.mu.Lock()
			old, retiring := c.current, c.retiring
			c.current = nil
			c.mu.Unlock()
			err := errors.Join(c.retire(retiring), c.retire(old))
			c.mu.Lock()
			c.closeErr = errors.Join(c.closeErr, err)
			c.notifyLocked(c.settled, c.settleErr)
			c.mu.Unlock()
			return
		case <-c.wake:
			if !c.stopping.Load() {
				c.reconcile(ctx)
			}
		}
	}
}

func (c *Controller) reconcile(ctx context.Context) {
	value, err := c.readAddress(ctx)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.requested = value
	if c.retiring != nil {
		c.mu.Unlock()
		return
	}
	if c.settled == value && !c.settling && c.settleErr == nil {
		c.notifyLocked(value, nil)
		c.mu.Unlock()
		return
	}
	old := c.current
	c.current = nil
	c.settling = true
	c.mu.Unlock()
	if err := c.retire(old); err != nil {
		c.mu.Lock()
		c.closeErr = errors.Join(c.closeErr, err)
		c.notifyLocked(value, err)
		c.mu.Unlock()
		c.cfg.Logger.Warn("diagnostics listener cleanup was not acknowledged")
		return
	}
	candidate, bindErr := c.newServer(ctx, value)
	published := false
	err = c.master.Do(ctx, func(context.Context) error {
		if c.stopping.Load() || c.master.Options.Str(addressOption) != value {
			return nil
		}
		c.mu.Lock()
		c.current = candidate
		c.notifyLocked(value, bindErr)
		c.mu.Unlock()
		published = true
		return nil
	})
	if !published {
		cleanupErr := c.retire(candidate)
		c.mu.Lock()
		c.closeErr = errors.Join(c.closeErr, cleanupErr)
		c.settling = false
		c.mu.Unlock()
		if err == nil {
			c.signal()
		}
		return
	}
	if bindErr != nil {
		c.cfg.Logger.Warn("diagnostics listener could not bind; choose a free loopback address", "address", value)
	}
}

func (c *Controller) notifyLocked(value string, err error) {
	c.settled, c.settleErr, c.settling = value, err, false
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *Controller) retire(g *serverGeneration) error {
	if g == nil {
		return nil
	}
	c.mu.Lock()
	c.retiring = g
	cleanup := c.closeContext
	if cleanup == nil {
		var cancel context.CancelFunc
		cleanup, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}
	grace, cancelGrace := context.WithTimeout(cleanup, time.Second)
	c.graceCancel = cancelGrace
	if c.stopping.Load() {
		cancelGrace()
	}
	c.mu.Unlock()
	err := g.stop(cleanup, grace)
	cancelGrace()
	c.mu.Lock()
	c.graceCancel = nil
	if err == nil {
		c.retiring = nil
	}
	c.mu.Unlock()
	return err
}

// Sync waits outside dispatch for the settled option and previous server join.
// A bind failure is returned without making the feature's startup fatal.
func (c *Controller) Sync(ctx context.Context) error {
	for {
		requested, err := c.readAddress(ctx)
		if err != nil {
			return err
		}
		c.mu.Lock()
		changed, started := c.changed, c.started
		settled, settling, settleErr, cleanupErr := c.settled, c.settling, c.settleErr, c.closeErr
		c.mu.Unlock()
		if cleanupErr != nil {
			return cleanupErr
		}
		if !started || requested == settled && !settling {
			return settleErr
		}
		select {
		case <-changed:
		case <-c.done:
			return errors.New("debugserver: controller is closed")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Status returns bounded requested-versus-actual state without dispatch access.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := Status{Requested: c.requested, Failed: c.settleErr != nil}
	select {
	case <-c.done:
		status.Stopped = true
	default:
	}
	if c.current != nil {
		select {
		case <-c.current.served:
			status.Failed = true
		default:
			status.Address, status.Enabled = c.current.address, true
		}
	}
	return status
}

// Close joins the worker, listener and active HTTP work under one five-second
// deadline. Repeated calls share the same result and completion acknowledgement.
func (c *Controller) Close(ctx context.Context) error {
	c.closeOnce.Do(func() {
		deadline := time.Now().Add(5 * time.Second)
		if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
			deadline = caller
		}
		cleanup, cancel := context.WithDeadline(context.Background(), deadline)
		c.stopping.Store(true)
		c.mu.Lock()
		c.closeContext, c.closeCancel = cleanup, cancel
		if c.workerCancel != nil {
			c.workerCancel()
		}
		if c.graceCancel != nil {
			c.graceCancel()
		}
		if !c.started {
			close(c.done)
		}
		c.mu.Unlock()
		close(c.stop)
	})
	select {
	case <-c.done:
	case <-ctx.Done():
		select {
		case <-c.done:
		default:
			return ctx.Err()
		}
	case <-c.closeContext.Done():
		select {
		case <-c.done:
		default:
			return errors.New("debugserver: shutdown was not acknowledged")
		}
	}
	c.closeCancel()
	c.mu.Lock()
	err := c.closeErr
	c.mu.Unlock()
	return err
}
