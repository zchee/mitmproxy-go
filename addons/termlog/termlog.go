// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package termlog prints application log records to a terminal or pipe.
package termlog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/vtcodes"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// TermLog controls a synchronous slog handler with upstream's terminal format.
// Output writes deliberately block, including when called under the addon
// dispatch lock, as upstream blocks its event loop on terminal writes.
// A separate mutex serializes writes from goroutines outside addon dispatch.
// The frontend installs LogHandler in its logger; this addon does not replace
// the process-wide default logger or subscribe to the deprecated add_log hook.
type TermLog struct {
	options   *options.Manager
	out       io.Writer
	hasVT     bool
	level     slog.LevelVar
	mu        sync.Mutex
	fatal     func(error)
	fatalOnce sync.Once
}

// New returns a terminal logger using opts. A nil writer means os.Stdout.
// A write failure calls fatal once with a [*master.ExitError] carrying exit
// status 1, the way upstream's handler exits the process when its terminal
// is gone; the program passes the master's fatal shutdown here. A nil fatal
// drops the notification; the failure is still returned by Handle.
func New(opts *options.Manager, w io.Writer, fatal func(error)) *TermLog {
	if w == nil {
		w = os.Stdout
	}
	return &TermLog{options: opts, out: w, hasVT: vtcodes.EnsureSupported(w), fatal: fatal}
}

// Load registers upstream's log verbosity option.
func (t *TermLog) Load(ctx context.Context, loader *addon.Loader) error {
	t.level.Set(slog.LevelInfo)
	return loader.AddOption(ctx, "termlog_verbosity", options.TypeStr, "info", "Log verbosity.", "error", "warn", "info", "alert", "debug")
}

// Configure applies a changed verbosity to the handler without changing the
// levels of other handlers in the frontend's logger.
func (t *TermLog) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["termlog_verbosity"]; !ok {
		return nil
	}
	var level slog.Level
	switch t.options.Str("termlog_verbosity") {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "alert":
		level = addon.LevelAlert
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return options.Errorf("Unknown log verbosity: %s", t.options.Str("termlog_verbosity"))
	}
	t.level.Set(level)
	return nil
}

// LogHandler returns a handler that prints accepted records synchronously.
// Compose it alongside master.LogHandler and errorcheck.LogHandler; the
// composed handler need not inspect Handle's error, because a write failure
// reaches the fatal callback given to [New]. Handle also returns the
// failure as a [*master.ExitError] with exit status 1.
func (t *TermLog) LogHandler() slog.Handler { return &handler{log: t} }

type handler struct {
	log    *TermLog
	attrs  string
	group  string
	client string
}

// Enabled reports whether the log level meets the configured verbosity.
func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.log.level.Level()
}

// Handle formats an enabled record and writes it to the configured output.
func (h *handler) Handle(ctx context.Context, record slog.Record) error {
	if !h.Enabled(ctx, record.Level) {
		return nil
	}
	stamp := record.Time
	if stamp.IsZero() {
		stamp = time.Now()
	}
	timestamp := "[" + stamp.Format("15:04:05.000") + "]"
	client := h.client
	var attrs strings.Builder
	attrs.WriteString(h.attrs)
	record.Attrs(func(a slog.Attr) bool { appendAttr(&attrs, h.group, a, &client); return true })
	message := record.Message + attrs.String()
	if client != "" {
		client = "[" + client + "]"
	}
	if h.log.hasVT {
		timestamp = (vtcodes.Style{FG: "cyan", Dim: new(true)}).Render(timestamp)
		if client != "" {
			client = (vtcodes.Style{FG: "yellow", Dim: new(true)}).Render(client)
		}
		color := ""
		switch record.Level {
		case slog.LevelError:
			color = "red"
		case slog.LevelWarn:
			color = "yellow"
		case addon.LevelAlert:
			color = "magenta"
		}
		message = (vtcodes.Style{FG: color}).Render(message)
	}
	h.log.mu.Lock()
	_, err := fmt.Fprintln(h.log.out, timestamp+client+" "+message)
	h.log.mu.Unlock()
	if err != nil {
		exit := &master.ExitError{Err: err}
		if h.log.fatal != nil {
			h.log.fatalOnce.Do(func() { h.log.fatal(exit) })
		}
		return exit
	}
	return nil
}

// WithAttrs returns a handler that includes the attributes in subsequent records.
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	var b strings.Builder
	b.WriteString(h.attrs)
	for _, a := range attrs {
		appendAttr(&b, h.group, a, &clone.client)
	}
	clone.attrs = b.String()
	return &clone
}

// WithGroup returns a handler that prefixes subsequent attribute names with the group.
func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.group += name + "."
	return &clone
}

func appendAttr(b *strings.Builder, group string, a slog.Attr, client *string) {
	if a.Equal(slog.Attr{}) {
		return
	}
	value := a.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		if a.Key != "" {
			group += a.Key + "."
		}
		for _, attr := range value.Group() {
			appendAttr(b, group, attr, client)
		}
		return
	}
	if group == "" && a.Key == "client" {
		*client = value.String()
		return
	}
	b.WriteString(" ")
	b.WriteString(group)
	b.WriteString(a.Key)
	b.WriteString("=")
	b.WriteString(value.String())
}
