// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Upstream test/mitmproxy/addons/test_termlog.py maps onto this file as
// follows:
//
//	test_output       -> TestOutput
//	test_styling      -> TestStyling
//	test_cannot_print -> TestCannotPrint
//	ensure_cleanup    -> not applicable: upstream removes its handler from
//	                     Python's global logging root; this addon never
//	                     installs a process-global handler (see the comment
//	                     at the end of this file).
package termlog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T, w io.Writer, fatal func(error)) (*TermLog, *addon.Manager) {
	t.Helper()
	opts := options.New()
	log := New(opts, w, fatal)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	return log, m
}

// TestOutput ports test_output and covers every verbosity choice.
func TestOutput(t *testing.T) {
	tests := map[string]struct{ min slog.Level }{
		"debug": {slog.LevelDebug}, "info": {slog.LevelInfo}, "alert": {addon.LevelAlert},
		"warn": {slog.LevelWarn}, "error": {slog.LevelError},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			log, m := setup(t, &out, nil)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options().Update(ctx, map[string]any{"termlog_verbosity": name})
			}); err != nil {
				t.Fatal(err)
			}
			logger := slog.New(log.LogHandler())
			levels := map[string]slog.Level{"debug message": slog.LevelDebug, "info message": slog.LevelInfo, "alert message": addon.LevelAlert, "warn message": slog.LevelWarn, "error message": slog.LevelError}
			for message, level := range levels {
				logger.Log(t.Context(), level, message)
			}
			for message, level := range levels {
				if got := strings.Contains(out.String(), message); got != (level >= tt.min) {
					t.Fatalf("message %q present=%v: %q", message, got, out.String())
				}
			}
			if strings.Contains(out.String(), "\x1b[") {
				t.Fatal("nonterminal received ANSI")
			}
		})
	}
}

func TestStyling(t *testing.T) {
	var out bytes.Buffer
	log, _ := setup(t, &out, nil)
	log.hasVT = true
	record := slog.NewRecord(time.Unix(0, 123000000).UTC(), slog.LevelWarn, "hello", 0)
	if err := log.LogHandler().Handle(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	want := "\x1b[36m\x1b[2m[00:00:00.123]\x1b[0m \x1b[33mhello\x1b[0m\n"
	if diff := gocmp.Diff(want, out.String()); diff != "" {
		t.Fatal(diff)
	}
}

func TestCannotPrint(t *testing.T) {
	reader, writer := io.Pipe()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	var (
		calls int
		got   error
	)
	log, _ := setup(t, writer, func(err error) { calls++; got = err })
	record := slog.NewRecord(time.Time{}, slog.LevelInfo, "cannot print", 0)
	err := log.LogHandler().Handle(t.Context(), record)
	exit, ok := errors.AsType[*master.ExitError](err)
	if !ok || exit.ExitCode() != 1 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("got %v, want exit 1 wrapping closed pipe", err)
	}
	// A later failure reports nothing more: the first one already ends the
	// process, as upstream's handler exits on its first failed print.
	if err := log.LogHandler().Handle(t.Context(), record); err == nil {
		t.Fatal("second Handle returned nil, want the write failure")
	}
	if calls != 1 {
		t.Fatalf("fatal was called %d times, want once", calls)
	}
	fatalExit, ok := errors.AsType[*master.ExitError](got)
	if !ok || fatalExit.ExitCode() != 1 || !errors.Is(got, io.ErrClosedPipe) {
		t.Fatalf("fatal received %v, want exit 1 wrapping closed pipe", got)
	}
}

// TestCannotPrintNilFatal drops the notification without a callback; Handle
// still returns the failure.
func TestCannotPrintNilFatal(t *testing.T) {
	reader, writer := io.Pipe()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	log, _ := setup(t, writer, nil)
	err := log.LogHandler().Handle(t.Context(), slog.NewRecord(time.Time{}, slog.LevelInfo, "cannot print", 0))
	if _, ok := errors.AsType[*master.ExitError](err); !ok {
		t.Fatalf("got %v, want an ExitError", err)
	}
}

func TestClientAndAttrs(t *testing.T) {
	var out bytes.Buffer
	log, _ := setup(t, &out, nil)
	handler := log.LogHandler().WithAttrs([]slog.Attr{slog.String("client", "127.0.0.1:8080")}).WithGroup("request").WithAttrs([]slog.Attr{slog.Int("id", 1)})
	record := slog.NewRecord(time.Unix(0, 0).UTC(), slog.LevelInfo, "hello", 0)
	record.AddAttrs(slog.String("path", "/"))
	if err := handler.Handle(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff("[00:00:00.000][127.0.0.1:8080] hello request.id=1 request.path=/\n", out.String()); diff != "" {
		t.Fatal(diff)
	}
}

func TestConcurrentOutput(t *testing.T) {
	var out bytes.Buffer
	log, _ := setup(t, &out, nil)
	logger := slog.New(log.LogHandler())
	var wg sync.WaitGroup
	for range 30 {
		wg.Go(func() { logger.InfoContext(t.Context(), "whole message") })
	}
	wg.Wait()
	if got := strings.Count(out.String(), "whole message\n"); got != 30 {
		t.Fatalf("got %d whole messages", got)
	}
}

func TestOption(t *testing.T) {
	_, m := setup(t, io.Discard, nil)
	o, ok := m.Options().Lookup("termlog_verbosity")
	if !ok {
		t.Fatal("missing option")
	}
	if diff := gocmp.Diff("info", o.Default()); diff != "" {
		t.Fatal(diff)
	}
	if o.Type() != options.TypeStr {
		t.Fatal(o.Type())
	}
	if diff := gocmp.Diff([]string{"error", "warn", "info", "alert", "debug"}, o.Choices()); diff != "" {
		t.Fatal(diff)
	}
	for line := range strings.SplitSeq(string(testutil.Fixture(t, "options-upstream.txt")), "\n") {
		if strings.HasPrefix(line, "termlog_verbosity\t") {
			if diff := gocmp.Diff(strings.Split(line, "\t")[3], o.Help()); diff != "" {
				t.Fatal(diff)
			}
		}
	}
}

// Upstream ensure_cleanup checks global logging handlers are uninstalled.
// This addon never installs a process-global handler; the frontend owns its
// logger and composes LogHandler explicitly, like the errorcheck addon.
