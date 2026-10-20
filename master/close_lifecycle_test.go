// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package master_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func TestBeforeClose(t *testing.T) {
	cleanupErr := errors.New("consumer cleanup failed")
	runningErr := options.Errorf("running failed")
	tests := map[string]struct {
		failAt                               int
		runningError, cleanupError, disabled bool
		want                                 []string
	}{
		"after_done":         {want: []string{"check", "setup", "check", "running", "check", "finish", "done", "before_close"}},
		"cleanup_error":      {cleanupError: true, want: []string{"check", "setup", "check", "running", "check", "finish", "done", "before_close"}},
		"running_error_wins": {runningError: true, cleanupError: true, want: []string{"check", "setup", "check", "running", "done", "before_close"}},
		"before_setup":       {failAt: 1, cleanupError: true, want: []string{"check", "before_close"}},
		"after_setup":        {failAt: 2, cleanupError: true, want: []string{"check", "setup", "check", "before_close"}},
		"after_running":      {failAt: 3, cleanupError: true, want: []string{"check", "setup", "check", "running", "check", "done", "before_close"}},
		"nil_default":        {disabled: true, want: []string{"check", "setup", "check", "running", "check", "finish", "done"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			type contextKey struct{}
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, "run-value"))
			defer cancel()
			var events []string
			var m *master.Master
			calls := 0
			r := &recorder{doneFn: cancel}
			cfg := master.Config{Options: options.NewManager(), Logger: discard}
			if !tt.disabled {
				cfg.BeforeClose = func(clean context.Context) error {
					calls++
					events = append(events, "before_close")
					if clean.Err() != nil || clean.Value(contextKey{}) != "run-value" {
						t.Errorf("cleanup context canceled or lost Run values")
					}
					if _, err := addon.Concurrent(clean, func(context.Context) error { return nil }); !errors.Is(err, addon.ErrNoDispatch) {
						t.Errorf("callback carried a dispatch frame: %v", err)
					}
					if got := slices.Contains(r.got(), "done"); got != (tt.failAt != 1 && tt.failAt != 2) {
						t.Errorf("Done before callback=%t", got)
					}
					if err := m.Do(clean, func(frame context.Context) error { return m.Options.Set(frame, "recorder_flag=true") }); err != nil {
						t.Errorf("dispatch during cleanup: %v", err)
					}
					if !slices.Contains(r.got(), "configure recorder_flag") {
						t.Error("manager was already closed before consumer cleanup")
					}
					slog.New(m.LogHandler()).InfoContext(clean, "consumer cleanup log")
					if err := m.LogHandler().Flush(clean); err != nil {
						t.Errorf("log consumer already closed before callback: %v", err)
					}
					if tt.cleanupError {
						return cleanupErr
					}
					return nil
				}
			}
			m = master.New(cfg)
			t.Cleanup(func() {
				if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
					t.Error(err)
				}
			})
			check := &startupCheck{events: &events, failAt: tt.failAt}
			server := &startupServer{setup: func(ctx context.Context) error {
				return m.Do(ctx, func(context.Context) error { events = append(events, "setup"); return nil })
			}}
			running := &startupRecorder{m: m, events: &events}
			if tt.runningError {
				running.err = runningErr
			}
			if err := m.Addons.Add(t.Context(), check, server, running, r); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- m.Run(ctx) }()
			err := startupResult(t, result)
			if tt.failAt != 0 {
				if _, ok := errors.AsType[*master.ExitError](err); !ok || errors.Is(err, cleanupErr) {
					t.Fatalf("startup error replaced by callback: %v", err)
				}
			} else {
				var want error
				if tt.runningError {
					want = runningErr
				} else if tt.cleanupError {
					want = cleanupErr
				}
				if !errors.Is(err, want) {
					t.Fatalf("Run error=%v want=%v", err, want)
				}
			}
			if diff := gocmp.Diff(tt.want, events); diff != "" {
				t.Fatalf("lifecycle order (-want +got):\n%s", diff)
			}
			wantCalls := 1
			if tt.disabled {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("callback calls=%d want=%d", calls, wantCalls)
			}
			if !tt.disabled {
				entries := r.logs()
				if len(entries) != 1 || !strings.HasSuffix(entries[0].Msg, "consumer cleanup log") {
					t.Fatalf("final log not delivered before Close: %v", entries)
				}
			}
			before := r.got()
			if err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Set(ctx, "recorder_flag=false") }); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(before, r.got()); diff != "" {
				t.Fatalf("manager remained subscribed after Close:\n%s", diff)
			}
		})
	}
}
