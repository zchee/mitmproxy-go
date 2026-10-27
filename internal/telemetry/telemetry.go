// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package telemetry owns opt-in flow telemetry for one Master. Construct a
// Controller with per-instance fidelity, connection-count and listener
// capabilities before master.New; supply its OnHookComplete, OnDispatchStart
// and OnDispatchEnd callbacks, then Bind the Master and add the controller to
// its default addons. Load registers the option; Running enables asynchronous
// settled-option reconciliation. Close must run outside dispatch and joins
// owned SDK/export/transport work before the Master's log consumers close.
package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

const endpointOption = "otel_exporter_endpoint"

// Config supplies capabilities owned by the containing proxy instance.
type Config struct {
	// Fidelity is the instance's cumulative HTTP emission-normalization count.
	Fidelity *http1.FidelityCounter
	// Connections reports active clients using the connection registry's Len.
	Connections func() int
	// Listeners returns actual proxy/debug listener tuples for recursion refusal.
	Listeners func() []netip.AddrPort
	// Version is the application's version, bounded to 128 exported bytes.
	Version string
	// Logger receives optional-feature failures without endpoint or flow data.
	Logger *slog.Logger
}

// Status contains bounded diagnostics, never intercepted flow or option data.
type Status struct {
	Enabled           bool  `json:"enabled"`
	ActiveFlows       int64 `json:"active_flows"`
	ActiveConnections int64 `json:"active_connections"`
	// HTTPFidelity is the instance's exact cumulative normalization count.
	HTTPFidelity     uint64 `json:"http_fidelity"`
	TerminalDisabled uint64 `json:"terminal_disabled"`
	InvalidMetadata  uint64 `json:"invalid_metadata"`
	QueuePressure    uint64 `json:"queue_pressure"`
	ExportFailures   uint64 `json:"export_failures"`
	Stopped          bool   `json:"stopped"`
}

// Controller owns scalar lifecycle state and one current exporter generation.
type Controller struct {
	cfg       Config
	master    *master.Master
	tlsConfig *tls.Config

	state            stateRegistry
	admit            sync.Mutex
	current          *generation
	admissionStopped bool
	flows            [5]atomic.Int64
	// Dispatch serializes the hold callbacks; the metric callback never reads this clock.
	dispatchStart  time.Time
	disabled       atomic.Uint64
	invalid        atomic.Uint64
	queuePressure  atomic.Uint64
	exportFailures atomic.Uint64
	stopping       atomic.Bool

	mu           sync.Mutex
	started      bool
	wake         chan struct{}
	stop         chan struct{}
	done         chan struct{}
	changed      chan struct{}
	settled      string
	settling     bool
	retiring     *generation
	settleErr    error
	workerCancel context.CancelFunc
	graceCancel  context.CancelFunc
	closeContext context.Context
	closeCancel  context.CancelFunc
	closeErr     error
	closeOnce    sync.Once
}

// New returns a disabled controller without starting workers or network I/O.
func New(cfg Config) *Controller {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Controller{cfg: cfg, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), changed: make(chan struct{}), state: newStateRegistry()}
}

// Bind supplies the Master after its observation callbacks have been installed.
// Call it once, before registering the controller or starting the Master.
func (c *Controller) Bind(m *master.Master) *Controller {
	c.master = m
	return c
}

// Name identifies the owning option/lifecycle addon.
func (*Controller) Name() string { return "telemetry" }

// Load registers the opt-in exporter control. It never constructs exporters.
func (c *Controller) Load(ctx context.Context, loader *addon.Loader) error {
	if c.master == nil {
		return errors.New("telemetry: Bind must precede addon registration")
	}
	return loader.AddOption(ctx, endpointOption, options.TypeStr, "", "OTLP endpoint that OpenTelemetry traces and metrics are exported to. Empty disables the exporter.")
}

// Configure validates syntax and publishes a coalesced wake without I/O.
func (c *Controller) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated[endpointOption]; !ok {
		return nil
	}
	if _, err := parseEndpoint(c.master.Options.Str(endpointOption)); err != nil {
		return err
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

// Running starts the sole reconciler; metadata-only construction stays inert.
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
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

// Done stops admitting reconfiguration; Close performs acknowledged cleanup.
func (c *Controller) Done(context.Context) error {
	c.stopping.Store(true)
	return nil
}

func (c *Controller) readEndpoint(ctx context.Context) (string, error) {
	var value string
	err := c.master.Do(ctx, func(context.Context) error {
		value = c.master.Options.Str(endpointOption)
		return nil
	})
	return value, err
}

func (c *Controller) run(ctx context.Context) {
	defer close(c.done)
	for {
		select {
		case <-c.stop:
			c.admit.Lock()
			g := c.current
			c.current = nil
			c.admit.Unlock()
			c.mu.Lock()
			cleanup := c.closeContext
			retiring := c.retiring
			c.mu.Unlock()
			retiredErr := c.retire(retiring, cleanup)
			var err error
			if retiredErr == nil {
				err = c.retire(g, cleanup)
			} else if g != nil {
				g.cancel()
				err = g.stop(cleanup, cleanup)
			}
			c.mu.Lock()
			c.closeErr = errors.Join(c.closeErr, retiredErr, err)
			close(c.changed)
			c.changed = make(chan struct{})
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
	c.mu.Lock()
	blocked := c.retiring != nil
	c.mu.Unlock()
	if blocked {
		return
	}
	value, err := c.readEndpoint(ctx)
	if err != nil {
		return
	}
	c.admit.Lock()
	old := c.current
	same := (old == nil && value == "") || (old != nil && old.endpoint == value)
	c.admit.Unlock()
	if same {
		c.notifySettled(value, nil)
		return
	}
	c.mu.Lock()
	c.settling = true
	c.mu.Unlock()
	candidate, err := c.newGeneration(ctx, value)
	if err != nil {
		c.cfg.Logger.Warn("telemetry exporter could not be configured")
		c.notifySettled(value, err)
		return
	}
	published := false
	err = c.master.Do(ctx, func(context.Context) error {
		if c.stopping.Load() || c.master.Options.Str(endpointOption) != value {
			return nil
		}
		c.admit.Lock()
		old, c.current = c.current, candidate
		c.admit.Unlock()
		published = true
		return nil
	})
	if !published {
		if cleanupErr := c.retire(candidate, nil); cleanupErr != nil {
			c.mu.Lock()
			c.closeErr = errors.Join(c.closeErr, cleanupErr)
			c.mu.Unlock()
			c.notifySettled(value, cleanupErr)
		}
		if err == nil {
			select {
			case c.wake <- struct{}{}:
			default:
			}
		}
		return
	}
	if err := c.retire(old, nil); err != nil {
		c.mu.Lock()
		c.closeErr = errors.Join(c.closeErr, err)
		c.mu.Unlock()
		c.cfg.Logger.Error("telemetry exporter cleanup was not acknowledged")
		c.notifySettled(value, err)
		return
	}
	c.notifySettled(value, nil)
}

func (c *Controller) retire(g *generation, cleanup context.Context) error {
	if g == nil {
		return nil
	}
	c.mu.Lock()
	interruptedReplacement := cleanup == nil && c.closeContext != nil
	if c.retiring != nil && c.retiring != g {
		c.mu.Unlock()
		return errors.New("telemetry: previous retirement has not been acknowledged")
	}
	c.retiring = g
	if c.closeContext != nil {
		cleanup = c.closeContext
	}
	if cleanup == nil {
		var cancel context.CancelFunc
		cleanup, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}
	grace, cancelGrace := context.WithTimeout(cleanup, 5*time.Second)
	c.graceCancel = cancelGrace
	if interruptedReplacement {
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

func (c *Controller) notifySettled(value string, err error) {
	c.mu.Lock()
	c.settled, c.settleErr = value, err
	c.settling = false
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
}

// Sync waits for the current settled option to be applied and old work joined.
// It must be called outside dispatch, not from an observation callback.
func (c *Controller) Sync(ctx context.Context) error {
	for {
		requested, err := c.readEndpoint(ctx)
		if err != nil {
			return err
		}
		c.mu.Lock()
		changed := c.changed
		value, settleErr, started, settling := c.settled, c.settleErr, c.started, c.settling
		blocked, cleanupErr := c.retiring != nil && c.closeErr != nil, c.closeErr
		c.mu.Unlock()
		if blocked {
			return cleanupErr
		}
		if !started {
			return nil
		}
		if requested == value && !settling {
			return settleErr
		}
		select {
		case <-changed:
		case <-c.done:
			return errors.New("telemetry: controller is closed")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Close finalizes copied active state once and joins owned work within one
// total ten-second budget. Repeated calls share its result and acknowledgement.
func (c *Controller) Close(ctx context.Context) error {
	c.closeOnce.Do(func() {
		deadline := time.Now().Add(10 * time.Second)
		if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
			deadline = caller
		}
		cleanup, cancel := context.WithDeadline(context.Background(), deadline)
		c.stopping.Store(true)
		c.mu.Lock()
		c.closeContext = cleanup
		c.closeCancel = cancel
		if c.workerCancel != nil {
			c.workerCancel()
		}
		if c.graceCancel != nil {
			c.graceCancel()
		}
		started := c.started
		c.mu.Unlock()
		c.finishActive()
		c.admit.Lock()
		c.admissionStopped = true
		c.admit.Unlock()
		close(c.stop)
		if !started {
			close(c.done)
		}
	})
	select {
	case <-c.done:
		c.closeCancel()
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closeContext.Done():
		select {
		case <-c.done:
			c.mu.Lock()
			err := c.closeErr
			c.mu.Unlock()
			return err
		default:
			return errors.New("telemetry: controller shutdown was not acknowledged")
		}
	}
}

// OnDispatchStart begins process-level hold accounting without flow access.
func (c *Controller) OnDispatchStart() { c.dispatchStart = time.Now() }

// OnDispatchEnd records a bounded SDK histogram sample without export I/O.
func (c *Controller) OnDispatchEnd() {
	start := c.dispatchStart
	c.dispatchStart = time.Time{}
	if start.IsZero() {
		return
	}
	seconds := time.Since(start).Seconds()
	if seconds < 0 {
		return
	}
	c.admit.Lock()
	if c.current != nil && !c.admissionStopped {
		c.current.hold.Record(context.Background(), seconds)
	}
	c.admit.Unlock()
}

// Status returns bounded local diagnostics without acquiring dispatch.
func (c *Controller) Status() Status {
	var active int64
	for i := range c.flows {
		active += c.flows[i].Load()
	}
	var connections int64
	if c.cfg.Connections != nil && !c.stopping.Load() {
		connections = int64(c.cfg.Connections())
	}
	var fidelity uint64
	if c.cfg.Fidelity != nil {
		fidelity = c.cfg.Fidelity.Load()
	}
	c.admit.Lock()
	enabled := c.current != nil && !c.admissionStopped
	c.admit.Unlock()
	return Status{Enabled: enabled, ActiveFlows: active, ActiveConnections: connections, HTTPFidelity: fidelity, TerminalDisabled: c.disabled.Load(), InvalidMetadata: c.invalid.Load(), QueuePressure: c.queuePressure.Load(), ExportFailures: c.exportFailures.Load(), Stopped: c.stopping.Load()}
}

func (c *Controller) registerMetrics(provider *sdkmetric.MeterProvider) (metric.Float64Histogram, error) {
	meter := provider.Meter("github.com/zchee/mitmproxy-go/internal/telemetry")
	connections, err := meter.Int64ObservableGauge("proxy.connections.active")
	if err != nil {
		return nil, err
	}
	flows, err := meter.Int64ObservableGauge("proxy.flows.active")
	if err != nil {
		return nil, err
	}
	fidelity, err := meter.Float64ObservableCounter("proxy.http_fidelity")
	if err != nil {
		return nil, err
	}
	hold, err := meter.Float64Histogram("proxy.dispatch.hold.duration", metric.WithUnit("s"))
	if err != nil {
		return nil, err
	}
	_, err = meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		var clients int64
		if c.cfg.Connections != nil && !c.stopping.Load() {
			clients = int64(c.cfg.Connections())
		}
		observer.ObserveInt64(connections, clients)
		for i, kind := range flowKinds {
			observer.ObserveInt64(flows, c.flows[i].Load(), metric.WithAttributes(attribute.String("flow_kind", kind)))
		}
		var count uint64
		if c.cfg.Fidelity != nil {
			count = c.cfg.Fidelity.Load()
		}
		observer.ObserveFloat64(fidelity, float64(count))
		return nil
	}, connections, flows, fidelity)
	return hold, err
}
