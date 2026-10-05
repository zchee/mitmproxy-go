// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package errorcheck stops startup when the application logs an error.
package errorcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/master"
)

// Config controls startup error reporting.
type Config struct {
	// Stderr receives the startup failure message. Nil means os.Stderr.
	Stderr io.Writer
	// RepeatErrorsOnStderr includes each collected error after the summary.
	RepeatErrorsOnStderr bool
}

// ErrorCheck collects errors until startup finishes. Its slog handler is
// synchronous: a bounded add_log queue could drop the only startup error.
// A mutex protects only this collector, not addon or flow state, and is never
// held across dispatch. Methods are safe to call concurrently.
type ErrorCheck struct {
	mu       sync.Mutex
	stderr   io.Writer
	repeat   bool
	finished bool
	messages []string
}

// New returns a startup error collector. Install its LogHandler in the
// application's logger before loading and configuring addons.
func New(cfg Config) *ErrorCheck {
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	return &ErrorCheck{stderr: cfg.Stderr, repeat: cfg.RepeatErrorsOnStderr}
}

// Name identifies the startup checker to master.Run.
func (*ErrorCheck) Name() string { return "errorcheck" }

// LogHandler returns a synchronous handler for errors and more severe records.
// Compose it alongside master.LogHandler and the application's other outputs;
// this package does not replace the process-wide default logger.
func (e *ErrorCheck) LogHandler() slog.Handler { return &handler{collector: e} }

// ShutdownIfErrored prints the startup failure message and returns a
// master.ExitError with exit status 1 when errors were collected. Stderr write
// errors are retained in its cause. It never exits the process or dispatches
// hooks; the context is accepted to implement master.ErrorCheck.
func (e *ErrorCheck) ShutdownIfErrored(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.messages) == 0 {
		return nil
	}
	plural := ""
	if len(e.messages) > 1 {
		plural = "s"
	}
	summary := "Error" + plural + " logged during startup, exiting..."
	message := summary
	if e.repeat {
		message = "Error" + plural + " logged during startup:\n" + strings.Join(e.messages, "\n")
	}
	_, err := fmt.Fprintln(e.stderr, message)
	return &master.ExitError{Err: errors.Join(errors.New(summary), err)}
}

// Finish stops collection. Previously collected errors remain reportable,
// matching removal of the upstream logging handler without deleting its records.
func (e *ErrorCheck) Finish(context.Context) error {
	e.mu.Lock()
	e.finished = true
	e.mu.Unlock()
	return nil
}

type handler struct {
	collector *ErrorCheck
	attrs     []slog.Attr
	group     string
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	h.collector.mu.Lock()
	defer h.collector.mu.Unlock()
	return level >= slog.LevelError && !h.collector.finished
}

func (h *handler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level < slog.LevelError {
		return nil
	}
	message := record.Message
	if len(h.attrs) != 0 || record.NumAttrs() != 0 {
		var output bytes.Buffer
		formatter := slog.NewTextHandler(&output, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
				return slog.Attr{}
			}
			return a
		}}).WithAttrs(h.attrs).WithGroup(h.group)
		if err := formatter.Handle(ctx, record); err != nil {
			return err
		}
		if attrs := strings.TrimSpace(output.String()); attrs != "" {
			message += " " + attrs
		}
	}
	h.collector.mu.Lock()
	defer h.collector.mu.Unlock()
	if !h.collector.finished {
		h.collector.messages = append(h.collector.messages, message)
	}
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = slices.Clone(h.attrs)
	if h.group != "" {
		attrs = []slog.Attr{slog.GroupAttrs(h.group, attrs...)}
	}
	clone.attrs = append(clone.attrs, attrs...)
	return &clone
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	if clone.group != "" {
		clone.group += "."
	}
	clone.group += name
	return &clone
}

var _ master.ErrorCheck = (*ErrorCheck)(nil)
