// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package eventstore

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

func TestEventStoreLogHandler(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"registration_has_no_deprecation_warning": {run: func(t *testing.T) {
			store, err := New()
			must(t, err)
			if _, ok := any(store).(addon.AddLogHandler); ok {
				t.Fatal("eventstore still implements the deprecated log hook")
			}
			var output bytes.Buffer
			manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{Logger: slog.New(slog.NewTextHandler(&output, nil))})
			defer manager.Close()
			must(t, manager.Add(t.Context(), store))
			if diff := gocmp.Diff("", output.String()); diff != "" {
				t.Fatal("registering eventstore logged a warning: " + diff)
			}
		}},
		"slog_delivery_uses_dispatch": {run: func(t *testing.T) {
			store, err := New()
			must(t, err)
			active := false
			manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{
				OnDispatchStart: func() { active = true },
				OnDispatchEnd:   func() { active = false },
			})
			defer manager.Close()
			must(t, manager.Add(t.Context(), store))
			var observed []Event
			var queued <-chan Event
			must(t, manager.Do(t.Context(), func(context.Context) error {
				store.Observe(func(event Event) {
					if !active {
						t.Error("log observer ran outside addon dispatch")
					}
					observed = append(observed, event)
				})
				queued, _ = store.Subscribe(4)
				return nil
			}))
			handler := store.LogHandler(manager)
			defer func() { must(t, handler.Close(t.Context())) }()
			logger := slog.New(handler).WithGroup("request").With("id", 42)
			must(t, manager.Do(t.Context(), func(ctx context.Context) error {
				logger.WarnContext(ctx, "inside hook")
				return nil
			}))
			logger.InfoContext(t.Context(), "outside hook")
			must(t, handler.Flush(t.Context()))
			must(t, manager.Do(t.Context(), func(context.Context) error {
				records := store.Records()
				if len(records) != 2 || !strings.HasSuffix(records[0].Entry.Msg, "inside hook request.id=42") || !strings.HasSuffix(records[1].Entry.Msg, "outside hook request.id=42") {
					t.Fatalf("missing or unordered slog entries: %v", records)
				}
				if diff := gocmp.Diff([]slog.Level{slog.LevelWarn, slog.LevelInfo}, []slog.Level{records[0].Entry.Level, records[1].Entry.Level}); diff != "" {
					t.Fatal(diff)
				}
				want := []Event{{Kind: "add", ID: 1, Entry: records[0].Entry}, {Kind: "add", ID: 2, Entry: records[1].Entry}}
				if diff := gocmp.Diff(want, observed); diff != "" {
					t.Fatal(diff)
				}
				if len(queued) != len(want) {
					t.Fatalf("queued log additions = %d, want %d", len(queued), len(want))
				}
				if diff := gocmp.Diff(want, []Event{<-queued, <-queued}); diff != "" {
					t.Fatal(diff)
				}
				return nil
			}))
		}},
		"closing_handler_drains_and_stops_delivery": {run: func(t *testing.T) {
			store, err := New()
			must(t, err)
			manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
			defer manager.Close()
			must(t, manager.Add(t.Context(), store))
			handler := store.LogHandler(manager)
			defer func() { must(t, handler.Close(t.Context())) }()
			logger := slog.New(handler)
			for range 3 {
				logger.InfoContext(t.Context(), "before close")
			}
			must(t, handler.Close(t.Context()))
			logger.InfoContext(t.Context(), "after close")
			must(t, manager.Do(t.Context(), func(context.Context) error {
				records := store.Records()
				if len(records) != 3 || records[2].ID != 3 {
					t.Fatalf("close lost accepted entries or admitted later delivery: %v", records)
				}
				return nil
			}))
		}},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}
