// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package master_test

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const deadlockTimeout = 5 * time.Second

// within fails the test when fn does not return within deadlockTimeout.
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(deadlockTimeout):
		t.Fatalf("%s did not finish within %v", what, deadlockTimeout)
	}
}

// recorder is an addon that journals the hooks it receives and logs from
// its running hook.
type recorder struct {
	mu      sync.Mutex
	calls   []string
	entries []addon.LogEntry

	runningErr error
	logger     *slog.Logger  // when set, Running logs through it
	ran        chan struct{} // when set, closed by Running
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.calls = append(r.calls, s)
	r.mu.Unlock()
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func (r *recorder) Load(ctx context.Context, l *addon.Loader) error {
	r.add("load")
	return l.AddOption(ctx, "recorder_flag", options.TypeBool, false, "A flag the recorder watches.")
}

func (r *recorder) Configure(_ context.Context, updated map[string]struct{}) error {
	r.add("configure " + strings.Join(slices.Sorted(maps.Keys(updated)), ","))
	return nil
}

func (r *recorder) Running(ctx context.Context) error {
	r.add("running")
	if r.ran != nil {
		close(r.ran)
	}
	if r.logger != nil {
		r.logger.InfoContext(ctx, "logged from running")
	}
	return r.runningErr
}

func (r *recorder) Done(context.Context) error {
	r.add("done")
	return nil
}

func (r *recorder) AddLog(_ context.Context, e addon.LogEntry) error {
	r.mu.Lock()
	r.entries = append(r.entries, e)
	r.mu.Unlock()
	return nil
}

func (r *recorder) logs() []addon.LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.entries)
}

// discard keeps the manager's own warnings, such as the add_log
// deprecation notice, out of the test output.
var discard = slog.New(slog.DiscardHandler)

func newMaster(t *testing.T, r *recorder) *master.Master {
	t.Helper()
	m := master.New(master.Config{Options: options.NewManager(), Logger: discard})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), deadlockTimeout)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := m.Addons.Add(t.Context(), r); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return m
}

// TestDoOptionsSet changes an option inside master.Do; the configure hook
// the change fires re-enters the dispatch lock instead of deadlocking.
func TestDoOptionsSet(t *testing.T) {
	r := &recorder{}
	m := newMaster(t, r)
	within(t, "options.Set inside master.Do", func() {
		err := m.Do(t.Context(), func(ctx context.Context) error {
			return m.Options.Set(ctx, "recorder_flag=true")
		})
		if err != nil {
			t.Errorf("Do: %v", err)
		}
	})
	if !m.Options.Bool("recorder_flag") {
		t.Error("recorder_flag was not set")
	}
	if diff := cmp.Diff([]string{"load", "configure recorder_flag"}, r.got()); diff != "" {
		t.Errorf("hooks (-want +got):\n%s", diff)
	}
}

// TestLogReachesAddLog logs through the master's handler, once from a test
// goroutine and once from inside a hook that holds the dispatch lock.
func TestLogReachesAddLog(t *testing.T) {
	r := &recorder{}
	m := newMaster(t, r)
	logger := slog.New(m.LogHandler())
	r.logger = logger

	logger.Warn("from the test")
	within(t, "logging inside a hook", func() {
		if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
			t.Errorf("Trigger: %v", err)
		}
	})
	within(t, "Flush", func() {
		if err := m.LogHandler().Flush(t.Context()); err != nil {
			t.Errorf("Flush: %v", err)
		}
	})

	var got []string
	for _, e := range r.logs() {
		_, msg, _ := strings.Cut(e.Msg, "] ")
		got = append(got, e.LevelName()+" "+msg)
	}
	if diff := cmp.Diff([]string{"warn from the test", "info logged from running"}, got); diff != "" {
		t.Errorf("add_log entries (-want +got):\n%s", diff)
	}
}

func TestRun(t *testing.T) {
	tests := map[string]struct {
		runningErr error
		stop       func(m *master.Master, cancel context.CancelFunc)
		wantErr    bool
	}{
		"success: Shutdown stops Run": {
			stop: func(m *master.Master, _ context.CancelFunc) { m.Shutdown(); m.Shutdown() },
		},
		"success: cancelling the context stops Run": {
			stop: func(_ *master.Master, cancel context.CancelFunc) { cancel() },
		},
		"error: done runs after a failed running hook": {
			runningErr: options.Errorf("cannot start"),
			wantErr:    true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := &recorder{runningErr: tt.runningErr, ran: make(chan struct{})}
			m := newMaster(t, r)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			result := make(chan error, 1)
			go func() { result <- m.Run(ctx) }()
			if tt.stop != nil {
				// Stop only after the running hook has been dispatched, so
				// the test exercises the wait.
				within(t, "the running hook", func() { <-r.ran })
				tt.stop(m, cancel)
			}

			var err error
			within(t, "Run", func() { err = <-result })
			if _, isOpt := errors.AsType[*options.OptionsError](err); isOpt != tt.wantErr || (err != nil && !tt.wantErr) {
				t.Fatalf("Run error = %v, want an options error: %v", err, tt.wantErr)
			}
			if diff := cmp.Diff([]string{"load", "running", "done"}, r.got()); diff != "" {
				t.Errorf("hooks (-want +got):\n%s", diff)
			}
			// Run closed the master: option changes no longer reach the
			// addons.
			if err := m.Options.Set(t.Context(), "recorder_flag=true"); err != nil {
				t.Fatalf("Set after Run: %v", err)
			}
			if slices.Contains(r.got(), "configure recorder_flag") {
				t.Error("configure fired after Run returned")
			}
		})
	}
}

func TestNewDefaultsToCoreOptions(t *testing.T) {
	m := master.New(master.Config{Logger: discard})
	defer func() {
		if err := m.Close(t.Context()); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	for _, name := range []string{"listen_port", "mode", "ssl_insecure"} {
		if !m.Options.Has(name) {
			t.Errorf("core option %q is missing", name)
		}
	}
}

// commandCaller calls a command through the master from its running hook.
type commandCaller struct {
	m   *master.Master
	got any
	err error
}

func (c *commandCaller) Running(ctx context.Context) error {
	c.got, c.err = c.m.Call(ctx, "probe.held")
	return nil
}

// TestCall runs a command through the master from a goroutine outside the
// hooks and from inside a hook. Both run it under the dispatch lock; the
// call from the hook re-enters the hook's hold instead of deadlocking.
func TestCall(t *testing.T) {
	var held atomic.Bool
	m := master.New(master.Config{
		Options:         options.NewManager(),
		Logger:          discard,
		OnDispatchStart: func() { held.Store(true) },
		OnDispatchEnd:   func() { held.Store(false) },
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), deadlockTimeout)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := m.Commands.Register("probe.held", func() bool { return held.Load() }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	var (
		got any
		err error
	)
	within(t, "master.Call", func() { got, err = m.Call(t.Context(), "probe.held") })
	if err != nil || got != true {
		t.Errorf("Call = %v, %v; want true (run under the dispatch lock)", got, err)
	}

	c := &commandCaller{m: m}
	if err := m.Addons.Add(t.Context(), c); err != nil {
		t.Fatalf("Add: %v", err)
	}
	within(t, "master.Call inside a hook", func() {
		if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
			t.Errorf("Trigger: %v", err)
		}
	})
	if c.err != nil || c.got != true {
		t.Errorf("Call in the hook = %v, %v; want true", c.got, c.err)
	}
}
