// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	teatest "github.com/charmbracelet/x/exp/teatest/v2"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func testBridge(t *testing.T) (*Bridge, chan time.Time) {
	t.Helper()
	m := master.New(master.Config{})
	v := view.New(m.Addons)
	events, err := eventstore.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Add(t.Context(), v, events); err != nil {
		t.Fatal(err)
	}
	ticks := make(chan time.Time)
	b, err := NewBridge(context.WithoutCancel(t.Context()), BridgeConfig{Master: m, View: v, Events: events, Ticks: ticks, Project: func(flows []flow.Flow, r contract.ProjectionRequest) contract.Projection {
		p := contract.Projection{Total: len(flows), FocusID: r.FocusID, FocusIndex: r.FocusIndex}
		for i, f := range flows {
			p.IDs = append(p.IDs, f.Common().ID)
			if i >= r.Viewport.Offset && i < r.Viewport.Offset+r.Viewport.Height {
				p.Rows = append(p.Rows, contract.Row{ID: f.Common().ID, Type: f.Type()})
			}
		}
		return p
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	return b, ticks
}

func mustConsole(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func awaitConsole[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
		var zero T
		return zero
	}
}

type heldModel struct {
	model            *Model
	once             sync.Once
	entered, release chan struct{}
	frames           chan contract.Snapshot
	sizes            chan tea.WindowSizeMsg
}

func (m *heldModel) Init() tea.Cmd  { return m.model.Init() }
func (m *heldModel) View() tea.View { return m.model.View() }
func (m *heldModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if _, ok := msg.(contract.SnapshotMsg); ok {
		m.once.Do(func() { close(m.entered); <-m.release })
	}
	_, cmd := m.model.Update(msg)
	if _, ok := msg.(tea.WindowSizeMsg); ok {
		m.sizes <- tea.WindowSizeMsg{Width: m.model.width, Height: m.model.height}
	}
	if snapshot, ok := msg.(contract.SnapshotMsg); ok && m.model.snapshot.Generation == snapshot.Snapshot.Generation {
		m.frames <- m.model.snapshot
	}
	return m, cmd
}

func verifyAssembledUpdateBlocked(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	t.Cleanup(cancel)
	opts := options.New()
	mustConsole(t, opts.Update(ctx, map[string]any{"confdir": t.TempDir(), "server": false}))
	m, err := New(ctx, Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard})
	mustConsole(t, err)
	t.Cleanup(func() { mustConsole(t, m.Close(context.WithoutCancel(t.Context()))) })
	ticks := make(chan time.Time)
	m.Bridge.cfg.Ticks = ticks
	model, err := m.NewModel()
	mustConsole(t, err)
	probe := &integrationReady{ready: make(chan struct{})}
	mustConsole(t, m.Addons.Add(ctx, probe))
	held := &heldModel{model: model, entered: make(chan struct{}), release: make(chan struct{}), frames: make(chan contract.Snapshot, 1), sizes: make(chan tea.WindowSizeMsg, 2)}
	tm := teatest.NewTestModel(t, held, teatest.WithInitialTermSize(80, 24), teatest.WithProgramOptions(tea.WithContext(m.Bridge.Context())))
	finished := make(chan error, 1)
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(held.release) })
		mustConsole(t, tm.Quit())
		tm.WaitFinished(t, teatest.WithFinalTimeout(5*time.Second))
		m.Shutdown()
		select {
		case err := <-finished:
			mustConsole(t, err)
		case <-time.After(5 * time.Second):
			t.Error("assembled blocked-update lifecycle did not join")
		}
	})
	go func() { finished <- m.Run(ctx) }()
	select {
	case <-probe.ready:
	case err := <-finished:
		finished <- err
		t.Fatalf("assembled lifecycle failed before running: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("assembled lifecycle did not reach running")
	}
	// Both startup resizes must precede manually admitted snapshots.
	for range 2 {
		select {
		case size := <-held.sizes:
			if size.Width != 80 || size.Height != 24 {
				t.Fatalf("unexpected startup size: %+v", size)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("startup resize was not installed before watchdog")
		}
	}
	go m.Bridge.DrainTo(tm.Send)()
	go m.Bridge.DeliverEffectsTo(tm.Send)()
	ticks <- time.Unix(1, 0)
	awaitConsole(t, held.entered)
	ids := make([]string, 0, 10_000)
	for index := range 10_000 {
		f := testflow.TFlow()
		f.Live = false
		f.Request.TimestampStart = float64(index + 1)
		f.Request.Path = fmt.Sprintf("/blocked/%05d", index)
		ids = append(ids, f.ID)
		mustConsole(t, m.LoadFlow(t.Context(), f))
	}
	mustConsole(t, m.Do(t.Context(), func(context.Context) error {
		if m.View.Len() != len(ids) {
			t.Fatalf("loaded hooks retained %d flows, want %d while Update is held", m.View.Len(), len(ids))
		}
		return nil
	}))
	// Drain owned log work before admitting the final snapshot, not with a sleep.
	mustConsole(t, m.Master.LogHandler().Flush(t.Context()))
	mustConsole(t, m.eventLogs.Flush(t.Context()))
	releaseOnce.Do(func() { close(held.release) })
	ticks <- time.Unix(1, int64(FrameInterval))
	final := awaitConsole(t, held.frames)
	if final.Total != len(ids) || !slices.Equal(ids, final.IDs) {
		t.Fatal("assembled blocked Update lost produced flows or order")
	}
	tests := map[string]struct{ offset, index int }{
		"first": {0, 0}, "last": {-1, len(ids) - 1}, "deep": {5678, 5678},
	}
	admission := 2
	for name, test := range tests {
		_, err := m.Bridge.Call(t.Context(), "view.focus.go", test.offset)
		mustConsole(t, err)
		m.Bridge.RequestViewport(contract.Viewport{Offset: test.index, Width: 80, Height: 20})
		ticks <- time.Unix(1, int64(time.Duration(admission)*FrameInterval))
		admission++
		frame := awaitConsole(t, held.frames)
		if frame.Total != len(ids) || frame.FocusIndex != test.index || frame.FocusID != ids[test.index] || !slices.Equal(frame.IDs, ids) {
			t.Fatalf("%s navigation lost focus/order: total=%d index=%d id=%q", name, frame.Total, frame.FocusIndex, frame.FocusID)
		}
		if !slices.ContainsFunc(frame.Rows, func(row contract.Row) bool {
			return row.ID == ids[test.index] && strings.Contains(row.Text, fmt.Sprintf("/blocked/%05d", test.index))
		}) {
			t.Fatalf("%s navigation did not project the focused flow into the real list rows", name)
		}
		if len(frame.Rows) > 20 {
			t.Fatalf("%s navigation rendered %d rows for a 20-row viewport", name, len(frame.Rows))
		}
	}
}

func TestConsoleBridge(t *testing.T) {
	tests := map[string]struct{}{"update_blocked": {}, "send_outside_dispatch": {}, "dirty_race": {}, "cancel_join": {}, "command_fifo": {}, "command_busy": {}, "same_do_read_after_write": {}, "mixed_batches_same_do": {}, "saturated_no_state_change": {}, "sequence_installation": {}}
	t.Run("deterministic", func(t *testing.T) {
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				if name == "update_blocked" {
					verifyAssembledUpdateBlocked(t)
					return
				}
				b, ticks := testBridge(t)
				if name == "command_fifo" || name == "sequence_installation" || name == "mixed_batches_same_do" || name == "same_do_read_after_write" {
					mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error { b.cfg.View.Add(ctx, []flow.Flow{testflow.TFlow()}); return nil }))
				}
				switch name {
				case "send_outside_dispatch", "dirty_race":
					entered, release := make(chan struct{}), make(chan struct{})
					delivered := make(chan contract.Snapshot, 2)
					go b.drain(func(msg tea.Msg) {
						close(entered)
						select {
						case <-release:
						case <-b.Context().Done():
							return
						}
						delivered <- msg.(contract.SnapshotMsg).Snapshot
					})
					ticks <- time.Unix(1, 0)
					awaitConsole(t, entered)
					mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
						b.Invalidate()
						return nil
					}))
					close(release)
					old := awaitConsole(t, delivered)
					if b.Accept(old) {
						t.Fatal("stale snapshot accepted after held delivery")
					}
					// The retained generation, not another producer event, drives the next frame.
					b.cancel()
					awaitConsole(t, b.done)
				case "cancel_join":
					verifyCommandJoin(t)
					entered := make(chan struct{})
					go b.drain(func(tea.Msg) { close(entered); <-b.Context().Done() })
					ticks <- time.Unix(1, 0)
					awaitConsole(t, entered)
					// Cancellation must release an uninstalled result and a blocked delivery.
					b.cancel()
					mustConsole(t, b.Close(context.WithoutCancel(t.Context())))
				case "command_fifo", "sequence_installation", "mixed_batches_same_do":
					ctx, finish := BeginInvocation(t.Context())
					mustConsole(t, b.Do(ctx, func(ctx context.Context) error {
						mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "options", Context: "options"}}))
						if name == "mixed_batches_same_do" {
							mustConsole(t, b.Control.Apply(t.Context(), contract.Action{Kind: "option", Value: "showhost"}, nil))
						}
						return b.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "flowview", Context: "flowview"}})
					}))
					batch := finish()
					installer := NewInstaller(b.Control)
					if name == "mixed_batches_same_do" {
						middle := <-b.Control.Mailbox()
						if len(installer.Install(contract.EffectsMsg{middle})) != 0 {
							t.Fatal("later external effect overtook invocation")
						}
					}
					if name == "sequence_installation" {
						if len(installer.Install(contract.EffectsMsg{batch[1]})) != 0 {
							t.Fatal("out of order effect installed")
						}
						installed := installer.Install(contract.EffectsMsg{batch[0], batch[0], batch[1]})
						if len(installed) != 2 {
							t.Fatalf("installed %d effects, want 2", len(installed))
						}
					} else {
						installer.Install(batch)
					}
					got, _ := installer.State().Current("", true)
					if got.Context != "flowview" {
						t.Fatalf("wrong installed context: %+v", got)
					}
					if len(installer.Install(batch)) != 0 {
						t.Fatal("duplicate batch installed")
					}
					if name == "sequence_installation" {
						verifyAmendedContract(t)
						verifyInstallerRecovery(t)
					}
				case "same_do_read_after_write":
					verifyModes(t)
					verifyDisplayAdmission(t)
					mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
						mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "options", Context: "options", Option: "showhost"}}))
						w, ok := b.Control.State().Current("options", false)
						if !ok || w.Option != "showhost" {
							t.Fatal("synchronous options focus not visible")
						}
						mustConsole(t, b.cfg.Master.Options.Update(ctx, map[string]any{"showhost": true}))
						option, _ := b.cfg.Master.Options.Lookup(w.Option)
						mustConsole(t, b.cfg.Master.Options.Update(ctx, map[string]any{w.Option: option.Default()}))
						mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "flowview", Context: "flowview"}}))
						mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "mode", Value: "raw"}))
						w, ok = b.Control.State().Current("flowview", false)
						if !ok || w.Mode != "raw" {
							t.Fatal("mode query did not observe previous command")
						}
						return nil
					}))
				case "command_busy", "saturated_no_state_change":
					ctx, finish := BeginInvocation(t.Context())
					for i := range EffectCapacity {
						callctx := t.Context()
						if i%2 == 0 {
							callctx = ctx
						}
						mustConsole(t, b.Dispatch(callctx, contract.Action{Kind: "pane"}))
					}
					before, sequence := b.Control.State(), b.Control.sequence
					changed := false
					err := b.Do(t.Context(), func(ctx context.Context) error {
						return b.Control.Apply(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "options", Context: "options"}}, func(context.Context) error { changed = true; return nil })
					})
					if _, ok := errors.AsType[*BusyError](err); !ok {
						t.Fatalf("got %v, want busy", err)
					}
					if changed || b.Control.sequence != sequence || cmp.Diff(before, b.Control.State()) != "" {
						t.Fatal("refused action changed state or sequence")
					}
					installer := NewInstaller(b.Control)
					installer.Install(finish())
					for range EffectCapacity / 2 {
						installer.Install(contract.EffectsMsg{<-b.Control.Mailbox()})
					}
					mustConsole(t, b.Dispatch(t.Context(), contract.Action{Kind: "pane"}))
				}
			})
		}
	})
}

type actionRecorder struct {
	actions   []contract.Action
	responses int
}

type widgetResponse struct{}

func (w *actionRecorder) SetSnapshot(contract.Snapshot) {}
func (w *actionRecorder) Resize(int, int)               {}
func (w *actionRecorder) View() string                  { return "prompt" }
func (w *actionRecorder) Update(message tea.Msg) (tea.Cmd, bool) {
	switch message := message.(type) {
	case contract.Action:
		w.actions = append(w.actions, message)
		return nil, true
	case widgetResponse:
		w.responses++
		return nil, true
	case tea.KeyPressMsg:
		w.responses++
		return nil, true
	}
	return nil, false
}

func verifyAmendedContract(t *testing.T) {
	t.Helper()
	b, _ := testBridge(t)
	widget, prompt := new(actionRecorder), new(actionRecorder)
	m := NewModel(b, map[string]WidgetFactory{
		"sequence":  func(contract.Host) contract.Widget { return widget },
		"commander": func(contract.Host) contract.Widget { return prompt },
	})
	ctx, finish := BeginInvocation(t.Context())
	request := contract.GridRequest{Title: "values", Option: "ignore_hosts", Rows: [][]string{{"before"}}}
	mustConsole(t, b.OpenGrid(ctx, request))
	request.Rows[0][0] = "after"
	captured := testflow.TFlow()
	captured.Request.RawContent = []byte("original")
	gridAction := contract.Action{Grid: &contract.GridRequest{Flow: captured, Target: contract.EditTarget{FlowID: captured.ID, Part: "request-body"}}}
	gridClone := gridAction.Clone()
	captured.Request.RawContent[0] = 'X'
	copied := gridClone.Grid.Flow.(*flow.HTTPFlow)
	if copied.ID != captured.ID || string(copied.Request.RawContent) != "original" || gridClone.Grid.Target.FlowID != captured.ID {
		t.Fatal("grid payload lost source identity or aliases captured flow bytes")
	}
	for _, direction := range []string{"start", "end", "next", "select", "up", "down", "pageup", "pagedown", "left", "right"} {
		mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "nav", Value: direction}))
	}
	for _, operation := range []string{"add", "insert", "delete", "load", "load_escaped", "save", "editor", "commit"} {
		mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "grid", Value: operation, Text: "operator.csv"}))
	}
	batch := finish()
	m.install(contract.EffectsMsg{batch[len(batch)-1]})
	if len(widget.actions) != 0 {
		t.Fatal("noncontiguous effect delivered")
	}
	m.install(batch)
	if len(widget.actions) != len(batch) || widget.actions[0].Grid.Rows[0][0] != "before" {
		t.Fatal("effect order or grid ownership lost")
	}
	m.install(batch)
	if len(widget.actions) != len(batch) {
		t.Fatal("effect delivered twice")
	}
	for _, action := range []contract.Action{{Kind: "nav", Value: "invalid"}, {Kind: "grid", Value: "invalid"}} {
		if b.Dispatch(t.Context(), action) == nil {
			t.Fatal("invalid action accepted")
		}
	}
	ctx, finish = BeginInvocation(t.Context())
	mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "keybindings", Context: "keybindings"}}))
	binding := b.Keys.Snapshot()[0]
	identity := binding.Key + "@" + strings.Join(binding.Contexts, ",")
	mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "binding", Value: identity}))
	mustConsole(t, b.Do(ctx, func(context.Context) error { return b.Keys.Remove(binding.Key, binding.Contexts) }))
	if b.Dispatch(ctx, contract.Action{Kind: "binding", Value: identity}) == nil {
		t.Fatal("stale binding identity accepted")
	}
	mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "binding", Value: ""}))
	mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "prompt", Value: "command", Text: "set x ''", Index: 7}))
	m.install(finish())
	if m.state.Prompt != "command" || m.state.Text != "set x ''" || m.state.Cursor != 7 {
		t.Fatal("prompt constructor contract changed")
	}
	m.Update(tea.KeyPressMsg{Code: 'x', Text: "x"})
	m.Update(widgetResponse{})
	if prompt.responses != 2 {
		t.Fatal("prompt input or private response not delivered")
	}
}

func verifyResults(t *testing.T) {
	t.Helper()
	b, _ := testBridge(t)
	m := NewModel(b, nil)
	tests := map[string]struct {
		value  any
		kind   string
		status string
	}{
		"nil": {nil, "", ""}, "empty string": {"", "text", ""}, "string": {"text\x1b[2J", "text", ""},
		"bytes": {[]byte{0, 255}, "bytes", ""}, "bool": {false, "text", ""}, "int": {0, "text", ""},
		"list": {[]string{}, "lines", ""}, "table": {command.Data{{"a", []byte{1}}}, "table", ""},
		"flow":          {testflow.TFlow(), "flow", "Command returned 1 flow"},
		"flows":         {[]flow.Flow{testflow.TFlow()}, "flows", "Command returned 1 flows"},
		"several flows": {[]flow.Flow{testflow.TFlow(), testflow.TFlow(), testflow.TFlow()}, "flows", "Command returned 3 flows"},
		"empty flows":   {[]flow.Flow{}, "flows", "Command returned 0 flows"},
	}
	for name, test := range tests {
		var result contract.Result
		mustConsole(t, b.Do(t.Context(), func(context.Context) error { var err error; result, err = b.projectResult(test.value); return err }))
		if result.Kind != test.kind {
			t.Fatalf("%s kind=%q want %q", name, result.Kind, test.kind)
		}
		_, cmd := m.Update(result)
		switch test.kind {
		case "flow", "flows":
			if m.message != test.status {
				t.Fatalf("%s status=%q want %q", name, m.message, test.status)
			}
			if cmd != nil {
				t.Fatal("flow result opened an overlay")
			}
		case "":
			if cmd != nil {
				t.Fatal("nil result opened an overlay")
			}
		default:
			if cmd == nil {
				t.Fatalf("%s did not open data viewer", name)
			}
			m.Update(cmd())
			window, ok := m.state.Current("dataviewer", true)
			if !ok || window.Name != "dataviewer" {
				t.Fatal("data viewer overlay missing")
			}
			widget := m.widget(m.state.Pane)
			if strings.Contains(widget.(*resultWidget).text, "\x1b") {
				t.Fatal("data viewer retained control bytes")
			}
			_, cmd = m.Update(resultMsg{effects: nil})
			if cmd != nil {
				m.Update(cmd())
			}
			m.Update(m.transition(contract.Action{Kind: "dismiss"})())
		}
	}
}

func verifyModes(t *testing.T) {
	t.Helper()
	b, _ := testBridge(t)
	f := testflow.TFlow()
	mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
		b.cfg.View.Add(ctx, []flow.Flow{f})
		_, err := b.Call(ctx, "view.settings.setval", []flow.Flow{f}, "flowview_mode_1", "raw")
		return err
	}))
	ctx, finish := BeginInvocation(t.Context())
	mustConsole(t, b.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "flowview", Context: "flowview", Index: 1}}))
	m := NewModel(b, nil)
	m.install(finish())
	w, _ := m.state.Current("flowview", false)
	if w.Mode != "raw" || w.Tab != "Response" || len(w.Tabs) != 3 {
		t.Fatalf("window not hydrated: %+v", w)
	}
	_, err := b.Call(t.Context(), "view.settings.setval", []flow.Flow{f}, "flowview_mode_1", "hex")
	mustConsole(t, err)
	snapshot, err := b.capture(b.generation.Load())
	mustConsole(t, err)
	m.applySnapshot(snapshot)
	w, _ = m.state.Current("flowview", false)
	if w.Mode != "hex" || w.Tabs[1].Mode != "hex" {
		t.Fatalf("snapshot did not use view-owned mode: %+v", w)
	}
	mustConsole(t, b.cfg.Master.Addons.Add(t.Context(), &ConsoleAddon{bridge: b}))
	other := testflow.TFlow()
	mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
		b.cfg.View.Add(ctx, []flow.Flow{other})
		if _, err := b.Call(ctx, "view.settings.setval", []flow.Flow{other}, "flowview_mode_1", "raw"); err != nil {
			return err
		}
		if _, err := b.Call(ctx, "view.focus.next"); err != nil {
			return err
		}
		mode, err := b.Call(ctx, "console.flowview.mode")
		if err != nil {
			return err
		}
		if mode != "raw" || b.cfg.View.Focus.Flow().Common().ID != other.ID {
			t.Fatalf("same-Do focus change read the old flow mode: %v", mode)
		}
		if err := b.Dispatch(ctx, contract.Action{Kind: "mode", Value: "json"}); err != nil {
			return err
		}
		return nil
	}))
	snapshot, err = b.capture(b.generation.Load())
	mustConsole(t, err)
	m.applySnapshot(snapshot)
	w, _ = m.state.Current("flowview", false)
	if w.FlowID != other.ID || w.Mode != "json" || w.Tabs[1].Mode != "json" {
		t.Fatalf("flow view did not follow the captured live focus: %+v", w)
	}
	ctx, finish = BeginInvocation(t.Context())
	mustConsole(t, b.Do(ctx, func(ctx context.Context) error {
		for range 2 {
			if err := b.Dispatch(ctx, contract.Action{Kind: "tab", Value: "next", Index: -1}); err != nil {
				return err
			}
		}
		window, _ := b.Control.State().Current("flowview", false)
		if window.Index != 0 {
			t.Fatalf("same-Do double tab ended at %d, want 0", window.Index)
		}
		mode, err := b.Call(ctx, "console.flowview.mode")
		if err != nil {
			return err
		}
		if mode != "auto" {
			t.Fatalf("relative tab query read the old tab mode: %v", mode)
		}
		return nil
	}))
	tabs := finish()
	if len(tabs) != 2 || tabs[0].Action.Index != 2 || tabs[0].Action.Value != "Detail" || tabs[1].Action.Index != 0 || tabs[1].Action.Value != "Request" {
		t.Fatalf("relative tab effects were not resolved to ordered absolute values: %+v", tabs)
	}
}

func verifyCommandJoin(t *testing.T) {
	t.Helper()
	b, _ := testBridge(t)
	entered, canceled, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	cmd := b.command(func() tea.Msg {
		close(entered)
		<-b.Context().Done()
		close(canceled)
		<-release
		return nil
	})
	go func() { cmd(); close(finished) }()
	awaitConsole(t, entered)
	closed := make(chan error, 1)
	go func() { closed <- b.Close(context.WithoutCancel(t.Context())) }()
	awaitConsole(t, canceled)
	select {
	case <-closed:
		t.Fatal("close returned while a command was active")
	default:
	}
	close(release)
	awaitConsole(t, finished)
	mustConsole(t, awaitConsole(t, closed))
	called := false
	b.command(func() tea.Msg { called = true; return nil })()
	if called {
		t.Fatal("queued command ran after close")
	}
}

func verifyLiveCadence(t *testing.T) {
	t.Helper()
	b, _ := testBridge(t)
	b.cfg.Ticks = nil
	starts := make(chan time.Time, 2)
	project := b.cfg.Project
	b.cfg.Project = func(fs []flow.Flow, r contract.ProjectionRequest) contract.Projection {
		starts <- time.Now()
		return project(fs, r)
	}
	frames := make(chan contract.Snapshot, 2)
	go b.drain(func(msg tea.Msg) { frames <- msg.(contract.SnapshotMsg).Snapshot })
	first := awaitConsole(t, frames)
	start := awaitConsole(t, starts)
	b.Invalidate()
	b.Accept(first)
	second := awaitConsole(t, frames)
	if next := awaitConsole(t, starts); next.Sub(start) < FrameInterval {
		t.Fatalf("traversals started only %s apart", next.Sub(start))
	}
	b.Accept(second)
}

func TestConsoleSnapshots(t *testing.T) {
	tests := map[string]struct{}{"detached": {}, "visible_rows": {}, "stale_generation": {}, "flow_removed": {}, "admitted_traversals": {}}
	t.Run("ownership", func(t *testing.T) {
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				b, ticks := testBridge(t)
				f := testflow.TFlow()
				mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error { b.cfg.View.Add(ctx, []flow.Flow{f}); return nil }))
				b.RequestViewport(contract.Viewport{Height: 1, Width: 80})
				snapshot, err := b.capture(b.generation.Load())
				mustConsole(t, err)
				switch name {
				case "detached":
					verifyResults(t)
					copy := snapshot.Clone()
					copy.Focused.(*flow.HTTPFlow).Request.Method = "DELETE"
					copy.IDs[0] = "changed"
					if snapshot.IDs[0] != f.ID || snapshot.Focused.Common().ID != f.ID || f.Request.Method == "DELETE" || snapshot.Focused.(*flow.HTTPFlow).Request.Method == "DELETE" {
						t.Fatal("snapshot aliases source or another copy")
					}
					if len(snapshot.Commands) == 0 || snapshot.Detail.Registry == nil {
						t.Fatal("command/detail seams missing")
					}
					completion, err := b.Complete(t.Context(), "view.o", "view.o")
					mustConsole(t, err)
					if !slices.Contains(completion.Choices, "view.order.options") {
						t.Fatalf("registry completion missing: %+v", completion)
					}
					mustConsole(t, b.Do(t.Context(), func(context.Context) error {
						if err := b.cfg.Master.Commands.Register("available", func(context.Context) []string {
							return []string{"beta value", "be        value", "be  value"}
						}); err != nil {
							return err
						}
						for _, name := range []string{"pick", "選択"} {
							if err := b.cfg.Master.Commands.Register(name, func(_ context.Context, _, _ string) {}, command.WithParams("choice", "suffix"), command.WithArgument("choice", command.Choice("available"))); err != nil {
								return err
							}
						}
						return nil
					}))
					tests := map[string]struct {
						prefix, full string
						start        int
					}{
						"tab-free control":        {"pick 'be", "pick 'be old' tail", 5},
						"tab before token":        {"pick\t'be", "pick\t'be old' tail", 5},
						"tab inside quoted token": {"pick 'be\t", "pick 'be\told' tail", 5},
						"multibyte before token":  {"選択 'be\t", "選択 'be\told' tail", 3},
					}
					for name, test := range tests {
						got, err := b.Complete(t.Context(), test.prefix, test.full)
						mustConsole(t, err)
						if got.Start != test.start {
							t.Errorf("%s raw rune token start = %d, want %d (prefix %q)", name, got.Start, test.start, test.prefix)
						}
						if diff := cmp.Diff([]string{"be        value", "be  value", "beta value"}, got.Choices); diff != "" {
							t.Error("raw choice mismatch (-want +got): " + diff)
						}
					}
					result, err := b.Execute(t.Context(), "view.order.options")
					mustConsole(t, err)
					if len(result.Lines) == 0 {
						t.Fatal("command result was not detached")
					}
					resolved, err := b.Resolve(t.Context(), contract.Recipe{Command: "view.order.options"}, "")
					mustConsole(t, err)
					if diff := cmp.Diff(result, resolved); diff != "" {
						t.Fatal(diff)
					}
					mustConsole(t, b.OpenGrid(t.Context(), contract.GridRequest{Title: "sequence", Option: "ignore_hosts", Rows: [][]string{{"example"}}}))
					window, _ := b.Control.State().Current("grideditor", false)
					if window.Option != "ignore_hosts" {
						t.Fatal("sequence editor target lost")
					}
					fingerprint := func(f flow.Flow, _ contract.EditTarget) ([32]byte, error) {
						return sha256.Sum256([]byte(f.(*flow.HTTPFlow).Request.Method)), nil
					}
					expected, _ := fingerprint(f, contract.EditTarget{})
					edit := contract.Edit{Target: contract.EditTarget{FlowID: f.ID, Part: "request", Fingerprint: expected}, Fingerprint: fingerprint, Apply: func(f flow.Flow, _ contract.EditTarget) { f.(*flow.HTTPFlow).Request.Method = "PATCH" }}
					mustConsole(t, b.CommitEdit(t.Context(), edit))
					if f.Request.Method != "PATCH" || !f.Modified() {
						t.Fatal("edit was not backed up/applied")
					}
					if !errors.Is(b.CommitEdit(t.Context(), edit), ErrEditConflict) {
						t.Fatal("stale fingerprint overwrote live changes")
					}
				case "visible_rows":
					if len(snapshot.Rows) != 1 || len(snapshot.IDs) != 1 || snapshot.Total != 1 {
						t.Fatalf("wrong projection: %+v", snapshot)
					}
					b.RequestViewport(contract.Viewport{Offset: 1, Height: 1})
					next, err := b.capture(b.generation.Load())
					mustConsole(t, err)
					if len(next.Rows) != 0 || len(next.IDs) != 1 {
						t.Fatal("viewport did not bound projected rows")
					}
				case "stale_generation":
					b.Invalidate()
					if b.Accept(snapshot) {
						t.Fatal("accepted stale generation")
					}
				case "flow_removed":
					mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
						_, err := b.Call(ctx, "view.flows.remove", []flow.Flow{f})
						return err
					}))
					next, err := b.capture(b.generation.Load())
					mustConsole(t, err)
					if next.Focused != nil || next.Total != 0 {
						t.Fatal("removed flow remained in snapshot")
					}
					edit := contract.Edit{Target: contract.EditTarget{FlowID: f.ID}, Fingerprint: func(flow.Flow, contract.EditTarget) ([32]byte, error) { return sha256.Sum256(nil), nil }, Apply: func(flow.Flow, contract.EditTarget) { t.Fatal("removed target mutated") }}
					if !errors.Is(b.CommitEdit(t.Context(), edit), ErrEditConflict) {
						t.Fatal("missing target did not conflict")
					}
				case "admitted_traversals":
					verifyLiveCadence(t)
					var traversals atomic.Int64
					project := b.cfg.Project
					b.cfg.Project = func(fs []flow.Flow, r contract.ProjectionRequest) contract.Projection {
						traversals.Add(1)
						return project(fs, r)
					}
					frames := make(chan contract.Snapshot)
					go b.drain(func(msg tea.Msg) { frames <- msg.(contract.SnapshotMsg).Snapshot })
					for range 100 {
						b.Invalidate()
					}
					ticks <- time.Unix(1, 0)
					first := awaitConsole(t, frames)
					for range 100 {
						b.Invalidate()
					}
					if traversals.Load() != 1 {
						t.Fatal("multiple traversals in flight")
					}
					b.Accept(first)
					ticks <- time.Unix(1, int64(8*time.Millisecond))
					ticks <- time.Unix(1, int64(16*time.Millisecond))
					second := awaitConsole(t, frames)
					if !b.Accept(second) || traversals.Load() != 2 {
						t.Fatalf("admitted traversals=%d, want 2", traversals.Load())
					}
					if !slices.Equal(second.IDs, []string{f.ID}) {
						t.Fatal("latest generation missing final flow")
					}
				}
			})
		}
	})
}
