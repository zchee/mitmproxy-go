// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package eventlog

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/options"
)

func logOptions(t *testing.T, verbosity string, follow bool) []options.Option {
	t.Helper()
	opts := options.NewManager()
	if err := opts.Add(t.Context(), "console_eventlog_verbosity", options.TypeStr, verbosity, ""); err != nil {
		t.Fatal(err)
	}
	if err := opts.Add(t.Context(), "console_focus_follow", options.TypeBool, follow, ""); err != nil {
		t.Fatal(err)
	}
	return opts.Items()
}

func TestConsoleEventLog(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"levels": {testLevels},
			"clear":  {testClear},
			"follow": {testFollow},
		}
		for name, test := range tests {
			t.Run(name, test.run)
		}
	})
}

func testLevels(t *testing.T) {
	entries := []eventstore.Record{
		{ID: 1, Entry: addon.LogEntry{Level: slog.LevelError, Msg: "error value"}},
		{ID: 2, Entry: addon.LogEntry{Level: slog.LevelWarn, Msg: "warn value"}},
		{ID: 3, Entry: addon.LogEntry{Level: slog.LevelInfo, Msg: "info value"}},
		{ID: 4, Entry: addon.LogEntry{Level: addon.LevelAlert, Msg: "alert value"}},
		{ID: 5, Entry: addon.LogEntry{Level: slog.LevelDebug, Msg: "debug value"}},
	}
	model := New(t.Context(), nil)
	model.Resize(40, 10)
	for verbosity, want := range map[string]int{"error": 1, "warn": 2, "info": 4, "alert": 4, "debug": 5} {
		model.SetSnapshot(contract.Snapshot{Events: entries, Options: logOptions(t, verbosity, false), Control: contract.NewState()})
		if diff := cmp.Diff(want, model.total); diff != "" {
			t.Fatalf("verbosity %s count (-want +got): %s", verbosity, diff)
		}
		for _, row := range model.rows {
			if !strings.Contains(model.View(), entries[row.index].Entry.Msg) {
				t.Fatalf("verbosity %s lost record %d", verbosity, row.id)
			}
		}
	}
	entries = []eventstore.Record{{ID: 6, Entry: addon.LogEntry{Level: slog.LevelInfo, Msg: "ＦＵＬＬ\n\x1b]52;c;payload\a"}}}
	model.Resize(12, 6)
	model.SetSnapshot(contract.Snapshot{Events: entries, Options: logOptions(t, "info", false), Control: contract.NewState()})
	if strings.Contains(model.View(), "\x1b]52") || strings.Contains(model.View(), "\a") {
		t.Fatal("untrusted log controls reached terminal")
	}
	if !strings.Contains(model.View(), "ＦＵＬ") {
		t.Fatalf("full-width log text lost: %q", model.View())
	}
}

func testClear(t *testing.T) {
	opts := options.NewManager()
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	store, err := eventstore.New(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	model := New(t.Context(), nil)
	model.Resize(40, 2)
	var firstID uint64
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		if err := store.Add(ctx, addon.LogEntry{Level: slog.LevelInfo, Msg: "before clear"}); err != nil {
			return err
		}
		firstID = store.Records()[0].ID
		model.SetSnapshot(contract.Snapshot{Events: store.Records(), Control: contract.NewState()})
		_, err := manager.Commands().Call(ctx, "eventstore.clear")
		if err != nil {
			return err
		}
		model.SetSnapshot(contract.Snapshot{Events: store.Records(), Control: contract.NewState()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if model.total != 0 || model.selected != 0 || len(model.rows) != 0 {
		t.Fatal("clear retained event selection or rows")
	}
	if strings.Contains(model.View(), "before clear") {
		t.Fatal("clear retained event text")
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		if err := store.Add(ctx, addon.LogEntry{Level: slog.LevelInfo, Msg: "after clear"}); err != nil {
			return err
		}
		model.SetSnapshot(contract.Snapshot{Events: store.Records(), Control: contract.NewState()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if model.selected <= firstID || !strings.Contains(model.View(), "after clear") {
		t.Fatal("event identity was reused or new row missing")
	}
}

func testFollow(t *testing.T) {
	model := New(t.Context(), nil)
	model.Resize(40, 2)
	state := contract.NewState()
	entries := []eventstore.Record{{ID: 1, Entry: addon.LogEntry{Level: slog.LevelInfo, Msg: "first"}}, {ID: 2, Entry: addon.LogEntry{Level: slog.LevelInfo, Msg: "second"}}}
	model.SetSnapshot(contract.Snapshot{Events: entries, Control: state, Options: logOptions(t, "info", false)})
	if model.selected != 1 {
		t.Fatalf("initial selection %d", model.selected)
	}
	entries = append(entries, eventstore.Record{ID: 3, Entry: addon.LogEntry{Level: slog.LevelInfo, Msg: "third"}})
	model.SetSnapshot(contract.Snapshot{Events: entries, Control: state, Options: logOptions(t, "info", false)})
	if model.selected != 1 {
		t.Fatal("disabled follow moved selection")
	}
	model.SetSnapshot(contract.Snapshot{Events: entries[1:], Control: state, Options: logOptions(t, "info", false)})
	if model.selected != 2 {
		t.Fatal("eviction did not select nearest surviving row")
	}
	entries = append(entries[1:], eventstore.Record{ID: 4, Entry: addon.LogEntry{Level: slog.LevelInfo, Msg: "fourth"}})
	model.SetSnapshot(contract.Snapshot{Events: entries, Control: state, Options: logOptions(t, "info", true)})
	if model.selected != 4 || !strings.Contains(model.View(), "fourth") {
		t.Fatal("follow did not expose newest event")
	}
	for range 2 {
		if cmd, consumed := model.Update(contract.Action{Kind: "nav", Value: "up"}); !consumed || cmd != nil {
			t.Fatal("event navigation must install locally without a dispatch command")
		}
	}
	if model.selected != 2 {
		t.Fatal("consecutive navigation effects did not advance the stable selection")
	}
	model.SetSnapshot(contract.Snapshot{Events: entries, Control: state, Options: logOptions(t, "info", true)})
	if model.selected != 2 {
		t.Fatal("unchanged newest ID overrode explicit navigation")
	}
	if _, consumed := model.Update(tea.KeyPressMsg{Code: 'q', Text: "q"}); consumed {
		t.Fatal("log captured global quit binding")
	}
	if cmd, consumed := model.Update(tea.MouseClickMsg{X: 0, Y: 0, Button: tea.MouseLeft}); !consumed || cmd != nil {
		t.Fatal("visible event mouse selection not consumed")
	}
	state.Mouse = false
	model.SetSnapshot(contract.Snapshot{Events: entries, Control: state})
	if _, consumed := model.Update(tea.MouseClickMsg{X: 0, Y: 0, Button: tea.MouseLeft}); consumed {
		t.Fatal("disabled mouse remained active")
	}
}
