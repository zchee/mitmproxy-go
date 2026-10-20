// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/anticache"
	"github.com/zchee/mitmproxy-go/addons/anticomp"
	"github.com/zchee/mitmproxy-go/addons/block"
	"github.com/zchee/mitmproxy-go/addons/blocklist"
	"github.com/zchee/mitmproxy-go/addons/browser"
	"github.com/zchee/mitmproxy-go/addons/clientplayback"
	"github.com/zchee/mitmproxy-go/addons/commandhistory"
	"github.com/zchee/mitmproxy-go/addons/comment"
	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/addons/cut"
	"github.com/zchee/mitmproxy-go/addons/disableh2c"
	"github.com/zchee/mitmproxy-go/addons/dnsresolver"
	"github.com/zchee/mitmproxy-go/addons/errorcheck"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/export"
	"github.com/zchee/mitmproxy-go/addons/intercept"
	"github.com/zchee/mitmproxy-go/addons/maplocal"
	"github.com/zchee/mitmproxy-go/addons/mapremote"
	"github.com/zchee/mitmproxy-go/addons/modifybody"
	"github.com/zchee/mitmproxy-go/addons/modifyheaders"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/onboarding"
	"github.com/zchee/mitmproxy-go/addons/proxyauth"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/readfile"
	"github.com/zchee/mitmproxy-go/addons/save"
	"github.com/zchee/mitmproxy-go/addons/savehar"
	"github.com/zchee/mitmproxy-go/addons/serverplayback"
	"github.com/zchee/mitmproxy-go/addons/stickyauth"
	"github.com/zchee/mitmproxy-go/addons/stickycookie"
	"github.com/zchee/mitmproxy-go/addons/stripdnshttpsrecords"
	"github.com/zchee/mitmproxy-go/addons/termlog"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/addons/updatealtsvc"
	"github.com/zchee/mitmproxy-go/addons/upstreamauth"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/tools/web/updates"
	"github.com/zchee/mitmproxy-go/internal/tools/web/webauth"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/httplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/modes"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/udplayer"
)

// Config configures the web master without starting listeners or browser work.
type Config struct {
	// Options is the shared registry; nil selects the core defaults.
	Options *options.Manager
	// Stdin supplies the rfile value "-"; nil selects os.Stdin.
	Stdin io.ReadCloser
	// Stdout receives terminal logs; nil selects os.Stdout.
	Stdout io.Writer
	// Stderr receives startup failures; nil selects os.Stderr.
	Stderr io.Writer
	// WithTermlog enables the terminal log addon.
	WithTermlog bool
}

// Master assembles the web frontend and the ported default addons.
// View and Events are protected by Do; ProxyServer publishes owned snapshots.
type Master struct {
	*master.Master
	View        *view.View
	Events      *eventstore.EventStore
	ProxyServer *proxyserver.ProxyServer

	logger     *slog.Logger
	auth       *webauth.WebAuth
	app        *application
	ready      chan struct{}
	running    atomic.Bool
	runDone    chan struct{}
	mu         sync.Mutex
	closed     bool
	lifetime   context.Context
	cancel     context.CancelFunc
	server     *http.Server
	addr       net.Addr
	served     chan struct{}
	browser    sync.WaitGroup
	hub        *updates.Hub
	eventLogs  *addon.LogHandler
	closeMu    sync.Mutex
	logsClosed bool
}

// logHandler is initialized before addon registration can emit any records.
type logHandler struct{ slog.Handler }

// New registers the upstream addon order without binding a listener, opening a
// browser or writing an export. The caller must Close a master it does not Run.
func New(ctx context.Context, cfg Config) (*Master, error) {
	opts := cfg.Options
	if opts == nil {
		opts = options.New()
	}
	handler := new(logHandler)
	logger := slog.New(handler)
	var m *Master
	base := master.New(master.Config{Options: opts, Logger: logger, BeforeClose: func(ctx context.Context) error { return m.closeFrontend(ctx) }})
	m = &Master{Master: base, logger: logger, ready: make(chan struct{}), runDone: make(chan struct{})}
	var err error
	m.Events, err = eventstore.New()
	if err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	m.eventLogs = m.Events.LogHandler(base.Addons)
	ec := errorcheck.New(errorcheck.Config{Stderr: cfg.Stderr})
	handlers := []slog.Handler{base.LogHandler(), m.eventLogs, ec.LogHandler()}
	var addons []any
	if cfg.WithTermlog {
		tl := termlog.New(opts, cfg.Stdout, m.ShutdownWithError)
		handlers = append(handlers, tl.LogHandler())
		addons = append(addons, tl)
	}
	handler.Handler = slog.NewMultiHandler(handlers...)
	ps, err := proxyserver.New(proxy.Config{Manager: base.Addons, Options: opts, Connections: new(proxy.Connections), HTTPFidelity: new(http1.FidelityCounter), Logger: logger})
	if err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	m.ProxyServer = ps
	m.View = view.New(base.Addons)
	m.auth = webauth.New(opts)
	addons = append(addons,
		core.New(base.Addons), browser.New(opts, base.Addons), block.New(opts),
		stripdnshttpsrecords.New(opts), blocklist.New(opts), anticache.New(opts), anticomp.New(opts),
		clientplayback.New(base), commandhistory.New(opts), comment.New(base.Addons), cut.New(),
		disableh2c.New(), export.New(opts), onboarding.New(opts), proxyauth.New(opts), ps,
		dnsresolver.New(opts, logger), nextlayer.New(opts), serverplayback.New(base),
		mapremote.New(opts), maplocal.New(opts), modifybody.New(opts), modifyheaders.New(opts),
		stickyauth.New(opts), stickycookie.New(opts), save.New(opts, m.ShutdownWithError),
		savehar.New(opts, version.Version), tlsconfig.New(opts), upstreamauth.New(opts), updatealtsvc.New(opts),
		&WebAddon{master: m}, m.auth, intercept.New(opts),
		readfile.New(base, readfile.Config{Stdin: cfg.Stdin, Logger: logger}),
		m.View, m.Events, ec,
	)
	if err := base.Addons.Add(ctx, addons...); err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	m.app = &application{master: base, view: m.View, events: m.Events, proxyserver: ps}
	m.app.useAuth(m.auth)
	m.hub, err = updates.New(ctx, updates.Config{Master: base, View: m.View, Events: m.Events, Servers: ps, Auth: m.auth})
	if err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	m.app.updates = m.hub
	return m, nil
}

// Logger returns the logger used by the addon and frontend lifecycle.
func (m *Master) Logger() *slog.Logger { return m.logger }

// Handler returns the authenticated HTTP frontend, usable without Run.
func (m *Master) Handler() http.Handler { return m.app.handler() }

// Ready closes after the HTTP listener has bound and serving has started.
// It does not close on a startup failure; also observe Run's return value.
func (m *Master) Ready() <-chan struct{} { return m.ready }

// WebAddr returns the actual bound address, or nil before the listener starts.
func (m *Master) WebAddr() net.Addr { m.mu.Lock(); defer m.mu.Unlock(); return m.addr }

// WebURL returns the current auth URL, including a token only in random-token mode.
// A requested ephemeral port is replaced with its actual bound port before Ready.
func (m *Master) WebURL() string { return m.auth.WebURL() }

// Run sets up the proxy, serves the UI and waits for cancellation or Shutdown.
// It must be called outside dispatch and at most once. All owned frontend work
// is canceled and joined outside dispatch before Run returns.
func (m *Master) Run(ctx context.Context) (err error) {
	if !m.running.CompareAndSwap(false, true) {
		return errors.New("web master already run")
	}
	defer close(m.runDone)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("web master is closed")
	}
	m.lifetime, m.cancel = context.WithCancel(ctx)
	life := m.lifetime
	m.mu.Unlock()
	return m.Master.Run(life)
}

// Shutdown cancels frontend requests immediately and asks the addon lifecycle
// to stop. It never waits for request handlers or browser work under dispatch.
func (m *Master) Shutdown() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	m.Master.Shutdown()
}

// ShutdownWithError cancels frontend work and records the first fatal error.
func (m *Master) ShutdownWithError(err error) {
	m.Master.ShutdownWithError(err)
	m.Shutdown()
}

// Close cancels HTTP requests and browser work and joins them outside dispatch.
// Calling it again is safe. Shutdown requests Run to stop; Close also releases
// resources when the master has never been run. Active requests have at most five
// seconds to drain, bounded further by ctx; a drain failure forces connection
// closure and is returned rather than being mistaken for a completed join.
func (m *Master) Close(ctx context.Context) error {
	m.Shutdown()
	if m.running.Load() {
		select {
		case <-m.runDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return errors.Join(m.closeFrontend(ctx), m.Master.Close(ctx))
}

func (m *Master) closeFrontend(ctx context.Context) error {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	m.Shutdown()
	drain, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	m.mu.Lock()
	m.closed = true
	cancel, server, served := m.cancel, m.server, m.served
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var err error
	if server != nil {
		err = server.Shutdown(drain)
		if err != nil {
			err = errors.Join(err, server.Close())
		}
	}
	if served != nil {
		select {
		case <-served:
		case <-drain.Done():
			err = errors.Join(err, drain.Err())
		}
	}
	if m.hub != nil {
		err = errors.Join(err, m.hub.Close(drain))
	}
	m.browser.Wait()
	if m.eventLogs != nil {
		if !m.logsClosed {
			err = errors.Join(err, m.Master.LogHandler().Flush(drain), m.eventLogs.Flush(drain))
			m.logsClosed = true
		}
		err = errors.Join(err, m.eventLogs.Close(drain))
	}
	return err
}
