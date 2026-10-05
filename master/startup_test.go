// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package master_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// Upstream test_master.py coverage:
// test_exception_handler: not applicable; Go has no asyncio task exception
// handler. Addon panic/error recovery is covered by addon/manager_test.go.

type startupCheck struct {
	events *[]string
	failAt int
	checks int
}

func (*startupCheck) Name() string { return "errorcheck" }
func (c *startupCheck) ShutdownIfErrored(context.Context) error {
	*c.events = append(*c.events, "check")
	c.checks++
	if c.checks == c.failAt {
		return &master.ExitError{Err: errors.New("startup failed")}
	}
	return nil
}

func (c *startupCheck) Finish(context.Context) error {
	*c.events = append(*c.events, "finish")
	return nil
}

type startupServer struct {
	setup func(context.Context) error
}

func (*startupServer) Name() string                             { return "proxyserver" }
func (s *startupServer) SetupServers(ctx context.Context) error { return s.setup(ctx) }

type startupRecorder struct {
	m      *master.Master
	events *[]string
	err    error
}

func (r *startupRecorder) Running(context.Context) error {
	*r.events = append(*r.events, "running")
	r.m.Shutdown()
	return r.err
}

func (r *startupRecorder) Done(context.Context) error {
	*r.events = append(*r.events, "done")
	return nil
}

var (
	_ master.ErrorCheck  = (*startupCheck)(nil)
	_ master.ServerSetup = (*startupServer)(nil)
)

func TestStartupSequence(t *testing.T) {
	tests := map[string]struct {
		failAt       int
		runningError bool
		want         []string
	}{
		"success: full sequence":          {want: []string{"check", "setup", "check", "running", "check", "finish", "done"}},
		"error: before setup":             {failAt: 1, want: []string{"check"}},
		"error: after setup":              {failAt: 2, want: []string{"check", "setup", "check"}},
		"error: after running":            {failAt: 3, want: []string{"check", "setup", "check", "running", "check", "done"}},
		"error: running still fires done": {runningError: true, want: []string{"check", "setup", "check", "running", "done"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := master.New(master.Config{})
			t.Cleanup(func() { _ = m.Close(t.Context()) })
			var events []string
			check := &startupCheck{events: &events, failAt: tt.failAt}
			server := &startupServer{setup: func(ctx context.Context) error {
				// Re-enter from setup's goroutine: setup must not own dispatch.
				return m.Do(ctx, func(context.Context) error {
					events = append(events, "setup")
					return nil
				})
			}}
			r := &startupRecorder{m: m, events: &events}
			if tt.runningError {
				r.err = &options.OptionsError{Msg: "running failed"}
			}
			if err := m.Addons.Add(t.Context(), check, server, r); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- m.Run(t.Context()) }()
			err := startupResult(t, result)
			if tt.failAt != 0 {
				if exit, ok := errors.AsType[*master.ExitError](err); !ok || exit.ExitCode() != 1 {
					t.Fatalf("Run error = %v, want ExitError with status 1", err)
				}
			} else if !errors.Is(err, r.err) {
				t.Fatalf("Run error = %v, want %v", err, r.err)
			}
			if diff := gocmp.Diff(tt.want, events); diff != "" {
				t.Fatalf("startup (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStartupShutdownCancelsSetup(t *testing.T) {
	tests := map[string]struct{ cancelContext bool }{
		"success: shutdown":             {},
		"success: context cancellation": {cancelContext: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := master.New(master.Config{})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			started, stopped := make(chan struct{}), make(chan struct{})
			var events []string
			s := &startupServer{setup: func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				defer close(stopped)
				return m.Do(context.WithoutCancel(ctx), func(context.Context) error { return nil })
			}}
			if err := m.Addons.Add(t.Context(), s, &startupRecorder{m: m, events: &events}); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- m.Run(ctx) }()
			startupSignal(t, started)
			if tt.cancelContext {
				cancel()
			} else {
				m.Shutdown()
			}
			if err := startupResult(t, result); err != nil {
				t.Fatal(err)
			}
			startupSignal(t, stopped)
			if len(events) != 0 {
				t.Fatalf("hooks ran before setup finished: %v", events)
			}
		})
	}
}

func TestExitError(t *testing.T) {
	cause := errors.New("cannot bind")
	err := &master.ExitError{Err: cause}
	if err.ExitCode() != 1 || !errors.Is(err, cause) || err.Error() != cause.Error() {
		t.Fatalf("exit error: code=%d cause=%v text=%q", err.ExitCode(), errors.Unwrap(err), err.Error())
	}
	if got := fmt.Sprint(&master.ExitError{}); got != "Error logged during startup, exiting..." {
		t.Fatalf("zero-value error = %q", got)
	}
}

func startupResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(10 * time.Second):
		buf := make([]byte, 1<<20)
		t.Fatalf("startup hung:\n%s", buf[:runtime.Stack(buf, true)])
		return nil
	}
}

func startupSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(10 * time.Second):
		buf := make([]byte, 1<<20)
		t.Fatalf("startup signal missing:\n%s", buf[:runtime.Stack(buf, true)])
	}
}
