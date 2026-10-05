// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package eventstore

import (
	"context"
	"log/slog"
	"maps"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamEventStore(t *testing.T) {
	tests := map[string]struct {
		size     []int
		messages []string
		want     []string
	}{
		"test_simple":   {nil, []string{"test"}, []string{"test"}},
		"test_max_size": {[]int{3}, []string{"foo", "bar", "baz", "boo"}, []string{"bar", "baz", "boo"}},
		"zero capacity": {[]int{0}, []string{"discard"}, []string{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			store, err := New(tt.size...)
			must(t, err)
			m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
			defer m.Close()
			must(t, m.Add(t.Context(), store))
			var events <-chan Event
			var cancel func()
			must(t, m.Do(t.Context(), func(context.Context) error { events, cancel = store.Subscribe(10); return nil }))
			handler := addon.NewLogHandler(func(ctx context.Context, entry addon.LogEntry) {
				if err := m.Trigger(ctx, addon.AddLogHook{Entry: entry}); err != nil {
					t.Error(err)
				}
			}, addon.LogHandlerOptions{})
			defer func() { must(t, handler.Close(t.Context())) }()
			logger := slog.New(handler)
			for _, msg := range tt.messages {
				logger.WarnContext(t.Context(), msg)
			}
			must(t, handler.Flush(t.Context()))
			must(t, m.Do(t.Context(), func(ctx context.Context) error {
				defer cancel()
				entries := store.Entries()
				got := make([]string, 0, len(entries))
				for _, entry := range entries {
					for _, msg := range tt.messages {
						if len(entry.Msg) >= len(msg) && entry.Msg[len(entry.Msg)-len(msg):] == msg {
							got = append(got, msg)
							break
						}
					}
				}
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Fatal(diff)
				}
				if len(events) != len(tt.messages) {
					t.Fatal("missing add signals")
				}
				for range tt.messages {
					if e := <-events; e.Kind != "add" {
						t.Fatal(e)
					}
				}
				_, err := m.Commands().CallStrings(ctx, "eventstore.clear", nil)
				if err != nil {
					return err
				}
				if len(store.Entries()) != 0 {
					t.Fatal("not cleared")
				}
				if e := <-events; e.Kind != "refresh" {
					t.Fatal(e)
				}
				return nil
			}))
		})
	}
}

func TestContract(t *testing.T) {
	store, err := New()
	must(t, err)
	if store.Size() != 10000 {
		t.Fatal(store.Size())
	}
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
	defer m.Close()
	must(t, m.Add(t.Context(), store))
	if len(m.Options().Items()) != 0 {
		t.Fatal("unexpected option")
	}
	commands := maps.Collect(m.Commands().Commands())
	if len(commands) != 1 || commands["eventstore.clear"].SignatureHelp() != "eventstore.clear " || commands["eventstore.clear"].Help != "Clear the event log." {
		t.Fatal(commands)
	}
	tests := map[string]struct{ sizes []int }{"negative": {[]int{-1}}, "extra argument": {[]int{1, 2}}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(tt.sizes...); err == nil {
				t.Fatal("invalid capacity accepted")
			}
		})
	}
}

func TestDispatchAndOverflow(t *testing.T) {
	active := false
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{OnDispatchStart: func() { active = true }, OnDispatchEnd: func() { active = false }})
	defer m.Close()
	store, err := New(3)
	must(t, err)
	must(t, m.Add(t.Context(), store))
	must(t, m.Do(t.Context(), func(ctx context.Context) error {
		slow, _ := store.Subscribe(1)
		fast, cancel := store.Subscribe(4)
		defer cancel()
		for range 2 {
			must(t, m.Trigger(ctx, addon.AddLogHook{Entry: addon.LogEntry{Msg: "x"}}))
		}
		if !active || len(fast) != 2 {
			t.Fatal("not delivered under dispatcher")
		}
		if _, ok := <-slow; !ok {
			t.Fatal("queued event discarded")
		}
		if _, ok := <-slow; ok {
			t.Fatal("overflow channel not closed")
		}
		return nil
	}))
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if err := m.Trigger(t.Context(), addon.AddLogHook{Entry: addon.LogEntry{Msg: "concurrent"}}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	must(t, m.Do(t.Context(), func(context.Context) error {
		if len(store.Entries()) != 3 {
			t.Fatal("ring bound")
		}
		return nil
	}))
}
