// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package keepserving

import (
	"context"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// counters registers the polled options and commands; its fields are guarded
// by the dispatch lock.
type counters struct {
	reading       bool
	clientReplays int
}

func (c *counters) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "rfile", options.TypeOptStr, nil, "Read flows from file."); err != nil {
		return err
	}
	if err := loader.AddCommand("readfile.reading", c.Reading); err != nil {
		return err
	}
	return loader.AddCommand("replay.client.count", c.ClientReplays)
}

func (c *counters) Reading(context.Context) bool      { return c.reading }
func (c *counters) ClientReplays(context.Context) int { return c.clientReplays }

func newServing(t *testing.T, interval time.Duration) (*master.Master, *KeepServing, *counters) {
	t.Helper()
	m := master.New(master.Config{})
	k := New(m, Config{Interval: interval})
	c := &counters{}
	if err := m.Addons.Add(t.Context(), k, c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Addons.Trigger(context.WithoutCancel(t.Context()), addon.DoneHook{}); err != nil {
			t.Error(err)
		}
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	return m, k, c
}

func wait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		t.Fatalf("watcher did not stop:\n%s", stack[:n])
	}
}

// Upstream test_keepserving checks keepgoing against active and idle
// replay state; absent commands and options must count as idle because the
// replay addons may not be loaded at all.
func TestKeepgoing(t *testing.T) {
	m, k, c := newServing(t, 0)
	if k.Keepgoing(t.Context()) {
		t.Fatal("idle commands reported as active")
	}
	if err := m.Do(t.Context(), func(context.Context) error { c.reading = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !k.Keepgoing(t.Context()) {
		t.Fatal("active reading not reported")
	}
	if err := m.Do(t.Context(), func(context.Context) error { c.reading = false; c.clientReplays = 3; return nil }); err != nil {
		t.Fatal(err)
	}
	if !k.Keepgoing(t.Context()) {
		t.Fatal("active replay count not reported")
	}
	if err := m.Do(t.Context(), func(context.Context) error { c.clientReplays = 0; return nil }); err != nil {
		t.Fatal(err)
	}
	if k.Keepgoing(t.Context()) {
		t.Fatal("idle counters reported as active")
	}
}

func TestKeepgoingWithoutCommands(t *testing.T) {
	m := master.New(master.Config{})
	t.Cleanup(func() { _ = m.Close(t.Context()) })
	k := New(m, Config{})
	if err := m.Addons.Add(t.Context(), k); err != nil {
		t.Fatal(err)
	}
	if k.Keepgoing(t.Context()) {
		t.Fatal("unknown commands reported as active")
	}
}

// Upstream test_keepserving's watch phase: once every polled source is idle
// the watcher shuts the master down and Run returns.
func TestWatchShutsDown(t *testing.T) {
	m, _, c := newServing(t, time.Millisecond)
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		c.reading = true
		return m.Options.Update(ctx, map[string]any{"rfile": new("flows")})
	}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); result <- m.Run(t.Context()) }()
	if err := m.Do(t.Context(), func(context.Context) error { c.reading = false; return nil }); err != nil {
		t.Fatal(err)
	}
	wait(t, finished)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestRunningSkipsWatcher(t *testing.T) {
	tests := map[string]struct {
		rfile       *string
		keepserving bool
	}{
		"success: nothing to wait for":  {},
		"success: keepserving selected": {rfile: new("flows"), keepserving: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, k, _ := newServing(t, time.Millisecond)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"rfile": tt.rfile, "keepserving": tt.keepserving})
			}); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
				t.Fatal(err)
			}
			if err := m.Do(t.Context(), func(context.Context) error {
				if k.done != nil {
					t.Error("watcher started")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDoneStopsWatcher(t *testing.T) {
	m, k, c := newServing(t, time.Hour)
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		c.reading = true
		return m.Options.Update(ctx, map[string]any{"rfile": new("flows")})
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	var done chan struct{}
	if err := m.Do(t.Context(), func(context.Context) error { done = k.done; return nil }); err != nil {
		t.Fatal(err)
	}
	if done == nil {
		t.Fatal("watcher not started")
	}
	if err := m.Addons.Trigger(t.Context(), addon.DoneHook{}); err != nil {
		t.Fatal(err)
	}
	wait(t, done)
}

func TestOptions(t *testing.T) {
	m, _, _ := newServing(t, 0)
	opt, ok := m.Options.Lookup("keepserving")
	if !ok {
		t.Fatal("missing option")
	}
	got := []any{opt.Type(), opt.Default(), opt.Help()}
	want := []any{options.TypeBool, false, "Continue serving after client playback, server playback or file read. This option is ignored by interactive tools, which always keep serving."}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatalf("option (-want +got):\n%s", diff)
	}
}
