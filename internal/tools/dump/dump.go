// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package dump assembles the mitmdump master: the addon set of
// mitmproxy's tools/dump.py, restricted to the ported addons.
package dump

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/zchee/mitmproxy-go/addons/block"
	"github.com/zchee/mitmproxy-go/addons/browser"
	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/addons/dumper"
	"github.com/zchee/mitmproxy-go/addons/errorcheck"
	"github.com/zchee/mitmproxy-go/addons/keepserving"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/onboarding"
	"github.com/zchee/mitmproxy-go/addons/proxyauth"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/readfile"
	"github.com/zchee/mitmproxy-go/addons/save"
	"github.com/zchee/mitmproxy-go/addons/termlog"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/addons/upstreamauth"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// Config configures a Master.
type Config struct {
	// Options is the option registry. Nil means [options.New], the core
	// options.
	Options *options.Manager

	// Stdout receives the dumper's flow output and the terminal log.
	// Nil means [os.Stdout].
	Stdout io.Writer

	// Stderr receives the startup failure message. Nil means [os.Stderr].
	Stderr io.Writer

	// Stdin is the stream the rfile value "-" reads. Nil means [os.Stdin];
	// see [readfile.Config].
	Stdin io.ReadCloser

	// WithTermlog registers the terminal logger, as upstream's Master does
	// under with_termlog.
	WithTermlog bool

	// WithDumper registers the flow dumper, as upstream's Master does
	// under with_dumper.
	WithDumper bool
}

// Master is a proxy master loaded with mitmdump's addon set, mitmproxy's
// DumpMaster.
type Master struct {
	*master.Master

	logger *slog.Logger
}

// New returns a Master whose addons are registered in upstream's
// order: the terminal logger first, then the ported subset of upstream's
// default_addons, then the dumper, and last the serving watchdog, the flow
// file reader and the startup error check.
//
// The default_addons entries without a ported counterpart are, in
// upstream's order: strip_dns_https_records, blocklist, anticache,
// anticomp, clientplayback, command_history, comment, cut, disable_h2c,
// export, script, dns_resolver, serverplayback, mapremote, maplocal,
// modifybody, modifyheaders, stickyauth, stickycookie, savehar and
// update_alt_svc.
func New(ctx context.Context, cfg Config) (*Master, error) {
	opts := cfg.Options
	if opts == nil {
		opts = options.New()
	}
	fan := &fanoutHandler{}
	logger := slog.New(fan)
	m := master.New(master.Config{Options: opts, Logger: logger})

	ec := errorcheck.New(errorcheck.Config{Stderr: cfg.Stderr})
	handlers := []slog.Handler{m.LogHandler(), ec.LogHandler()}
	var addons []any
	if cfg.WithTermlog {
		tl := termlog.New(opts, cfg.Stdout, m.ShutdownWithError)
		handlers = append(handlers, tl.LogHandler())
		addons = append(addons, tl)
	}
	fan.handlers = handlers

	ps, err := proxyserver.New(proxy.Config{
		Manager:      m.Addons,
		Options:      opts,
		Connections:  new(proxy.Connections),
		HTTPFidelity: new(http1.FidelityCounter),
		Logger:       logger,
	})
	if err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	addons = append(addons,
		core.New(m.Addons),
		browser.New(opts, m.Addons),
		block.New(opts),
		onboarding.New(opts),
		proxyauth.New(opts),
		ps,
		nextlayer.New(opts),
		save.New(opts, m.ShutdownWithError),
		tlsconfig.New(opts),
		upstreamauth.New(opts),
	)
	if cfg.WithDumper {
		addons = append(addons, dumper.New(opts, cfg.Stdout))
	}
	addons = append(addons,
		keepserving.New(m, keepserving.Config{}),
		readfile.New(m, readfile.Config{Stdin: cfg.Stdin, Logger: logger}),
		ec,
	)
	if err := m.Addons.Add(ctx, addons...); err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	return &Master{Master: m, logger: logger}, nil
}

// Logger returns the logger that fans every record out to the add_log
// hook, the startup error check and, when registered, the terminal log.
// The program installs it as the process default; tests read it directly.
func (m *Master) Logger() *slog.Logger { return m.logger }

// fanoutHandler delivers each record to every handler that accepts its
// level. Write failures need not be inspected here: the terminal logger
// reports its own failures through its fatal callback.
type fanoutHandler struct {
	handlers []slog.Handler
}

func (h *fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *fanoutHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, record.Level) {
			errs = append(errs, handler.Handle(ctx, record.Clone()))
		}
	}
	return errors.Join(errs...)
}

func (h *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithAttrs(attrs)
	}
	return &fanoutHandler{handlers: handlers}
}

func (h *fanoutHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithGroup(name)
	}
	return &fanoutHandler{handlers: handlers}
}
