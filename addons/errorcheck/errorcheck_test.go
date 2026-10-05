// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package errorcheck_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/errorcheck"
	"github.com/zchee/mitmproxy-go/master"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// Upstream test_no_error, test_error_message and test_repeat_error_on_stderr.
func TestStartupErrors(t *testing.T) {
	tests := map[string]struct {
		messages []string
		repeat   bool
		want     string
	}{
		"success: no error":      {},
		"error: single":          {messages: []string{"wat"}, want: "Error logged during startup, exiting...\n"},
		"error: multiple":        {messages: []string{"wat", "wat"}, want: "Errors logged during startup, exiting...\n"},
		"error: repeat":          {messages: []string{"wat"}, repeat: true, want: "Error logged during startup:\nwat\n"},
		"error: repeat multiple": {messages: []string{"one", "two"}, repeat: true, want: "Errors logged during startup:\none\ntwo\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			ec := errorcheck.New(errorcheck.Config{Stderr: &stderr, RepeatErrorsOnStderr: tt.repeat})
			logger := slog.New(ec.LogHandler())
			logger.WarnContext(t.Context(), "not an error")
			for _, message := range tt.messages {
				logger.ErrorContext(t.Context(), message)
			}
			err := ec.ShutdownIfErrored(t.Context())
			if len(tt.messages) == 0 {
				if err != nil {
					t.Fatal(err)
				}
			} else if exit, ok := errors.AsType[*master.ExitError](err); !ok || exit.ExitCode() != 1 {
				t.Fatalf("error = %v, want exit status 1", err)
			}
			if diff := gocmp.Diff(tt.want, stderr.String()); diff != "" {
				t.Fatalf("stderr (-want +got):\n%s", diff)
			}
			if err := ec.Finish(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type configureFailure struct{}

func (*configureFailure) Configure(context.Context, map[string]struct{}) error {
	return errors.New("configure failed")
}

// Upstream test_errorcheck uses a script load error; scripts are not required to
// exercise the same startup error path through a failing configure handler.
func TestConfigureErrorStopsRun(t *testing.T) {
	var stderr bytes.Buffer
	ec := errorcheck.New(errorcheck.Config{Stderr: &stderr})
	m := master.New(master.Config{Logger: slog.New(ec.LogHandler())})
	t.Cleanup(func() { _ = m.Close(t.Context()) })
	if err := m.Addons.Add(t.Context(), ec, &configureFailure{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.ConfigureHook{Updated: map[string]struct{}{}}); err != nil {
		t.Fatal(err)
	}
	// Run must fail before waiting for shutdown or entering running.
	if exit, ok := errors.AsType[*master.ExitError](m.Run(t.Context())); !ok || exit.ExitCode() != 1 {
		t.Fatalf("Run error = %v, want exit status 1", exit)
	}
	if diff := gocmp.Diff("Error logged during startup, exiting...\n", stderr.String()); diff != "" {
		t.Fatalf("stderr (-want +got):\n%s", diff)
	}
}

func TestFinishStopsCollection(t *testing.T) {
	var stderr bytes.Buffer
	ec := errorcheck.New(errorcheck.Config{Stderr: &stderr})
	logger := slog.New(ec.LogHandler())
	if err := ec.Finish(t.Context()); err != nil {
		t.Fatal(err)
	}
	logger.With("key", "value").WithGroup("group").ErrorContext(t.Context(), "late error")
	if err := ec.ShutdownIfErrored(t.Context()); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRepeatedAttributes(t *testing.T) {
	var stderr bytes.Buffer
	ec := errorcheck.New(errorcheck.Config{Stderr: &stderr, RepeatErrorsOnStderr: true})
	logger := slog.New(ec.LogHandler()).With("root", 1).WithGroup("outer").With("bound", 2).WithGroup("inner")
	logger.ErrorContext(t.Context(), "wat", "detail", 3)
	if err := ec.ShutdownIfErrored(t.Context()); err == nil {
		t.Fatal("missing startup failure")
	}
	want := "Error logged during startup:\nwat root=1 outer.bound=2 outer.inner.detail=3\n"
	if diff := gocmp.Diff(want, stderr.String()); diff != "" {
		t.Fatalf("stderr (-want +got):\n%s", diff)
	}
}

func TestStderrError(t *testing.T) {
	stderr, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stderr.Close(); err != nil {
		t.Fatal(err)
	}
	ec := errorcheck.New(errorcheck.Config{Stderr: stderr})
	slog.New(ec.LogHandler()).ErrorContext(t.Context(), "wat")
	err = ec.ShutdownIfErrored(t.Context())
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("error = %v, want closed stderr", err)
	}
	if exit, ok := errors.AsType[*master.ExitError](err); !ok || exit.ExitCode() != 1 {
		t.Fatalf("error = %v, want exit status 1", err)
	}
}

func TestConcurrentErrorsAreNotDropped(t *testing.T) {
	var stderr bytes.Buffer
	ec := errorcheck.New(errorcheck.Config{Stderr: &stderr, RepeatErrorsOnStderr: true})
	logger := slog.New(ec.LogHandler())
	var wg sync.WaitGroup
	for range 1000 {
		wg.Go(func() { logger.ErrorContext(t.Context(), "error") })
	}
	wg.Wait()
	if err := ec.ShutdownIfErrored(t.Context()); err == nil {
		t.Fatal("missing startup failure")
	}
	if got := strings.Count(stderr.String(), "error\n"); got != 1000 {
		t.Fatalf("repeated errors = %d, want 1000", got)
	}
}
