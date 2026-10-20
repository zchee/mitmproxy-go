// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package settings_test

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
	"github.com/zchee/mitmproxy-go/internal/tools/console/settings"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

type fixture struct {
	m      *master.Master
	bridge *console.Bridge
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	m := master.New(master.Config{})
	v := view.New(m.Addons)
	events, err := eventstore.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Add(t.Context(), core.New(m.Addons), v, events); err != nil {
		t.Fatal(err)
	}
	bridge, err := console.NewBridge(t.Context(), console.BridgeConfig{Master: m, View: v, Events: events, Project: func(flows []flow.Flow, _ contract.ProjectionRequest) contract.Projection {
		return contract.Projection{Total: len(flows)}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bridge.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	return fixture{m, bridge}
}

func key(name string) tea.KeyPressMsg {
	keys := map[string]rune{"up": tea.KeyUp, "down": tea.KeyDown, "enter": tea.KeyEnter, "esc": tea.KeyEscape, "home": tea.KeyHome, "end": tea.KeyEnd, "tab": tea.KeyTab}
	if code, ok := keys[name]; ok {
		return tea.KeyPressMsg{Code: code}
	}
	return tea.KeyPressMsg{Code: []rune(name)[0], Text: name}
}

func update(t *testing.T, widget contract.Widget, msg tea.Msg) []contract.ErrorMsg {
	t.Helper()
	cmd, _ := widget.Update(msg)
	return settle(t, widget, cmd)
}

func settle(t *testing.T, widget contract.Widget, cmd tea.Cmd) []contract.ErrorMsg {
	t.Helper()
	pending := []tea.Cmd{cmd}
	var failures []contract.ErrorMsg
	for n := 0; len(pending) > 0; n++ {
		if n > 1000 {
			t.Fatal("widget did not settle")
		}
		next := pending[0]
		pending = pending[1:]
		if next == nil {
			continue
		}
		switch result := next().(type) {
		case tea.BatchMsg:
			pending = append(pending, result...)
		case contract.ErrorMsg:
			failures = append(failures, result)
		default:
			following, _ := widget.Update(result)
			pending = append(pending, following)
		}
	}
	return failures
}

func (f fixture) options(t *testing.T, name string) *settings.Options {
	t.Helper()
	if err := f.bridge.Dispatch(t.Context(), contract.Action{Kind: "push", Window: contract.Window{Name: "options", Context: "options", Option: name}}); err != nil {
		t.Fatal(err)
	}
	if err := f.bridge.Dispatch(t.Context(), contract.Action{Kind: "option", Value: name}); err != nil {
		t.Fatal(err)
	}
	o := settings.NewOptions(t.Context(), f.bridge)
	o.SetSnapshot(f.snapshot(t))
	return o
}

func (f fixture) snapshot(t *testing.T) contract.Snapshot {
	t.Helper()
	var snapshot contract.Snapshot
	if err := f.bridge.Do(t.Context(), func(context.Context) error {
		snapshot.Control = f.bridge.Control.State()
		snapshot.Bindings = f.bridge.Keys.Snapshot()
		for _, name := range f.m.Options.Keys() {
			option, ok := f.m.Options.Lookup(name)
			if ok {
				snapshot.Options = append(snapshot.Options, option)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestConsoleOptionsEditor(t *testing.T) {
	t.Run("options", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"bool": func(t *testing.T) {
				f := newFixture(t)
				o := f.options(t, "showhost")
				update(t, o, key("enter"))
				if !f.m.Options.Bool("showhost") || o.Error() != nil {
					t.Fatalf("toggle failed: %v", o.Error())
				}
				o.SetSnapshot(f.snapshot(t))
				if !strings.Contains(o.View(), "true") {
					t.Fatal("current value not rendered")
				}
			},
			"scalar": func(t *testing.T) {
				f := newFixture(t)
				o := f.options(t, "listen_host")
				update(t, o, key("enter"))
				update(t, o, tea.PasteMsg{Content: "127.0.0.7"})
				update(t, o, key("enter"))
				if got := f.m.Options.Str("listen_host"); got != "127.0.0.7" {
					t.Fatal(got)
				}
			},
			"optional": func(t *testing.T) {
				f := newFixture(t)
				if err := f.m.Options.Add(t.Context(), "optional_number", options.TypeOptInt, nil, "optional integer"); err != nil {
					t.Fatal(err)
				}
				o := f.options(t, "optional_number")
				update(t, o, key("enter"))
				update(t, o, tea.PasteMsg{Content: "42"})
				update(t, o, key("enter"))
				option, _ := f.m.Options.Lookup("optional_number")
				if diff := gocmp.Diff(new(42), option.Current()); diff != "" {
					t.Fatal(diff)
				}
			},
			"choices": func(t *testing.T) {
				f := newFixture(t)
				if err := f.m.Options.Add(t.Context(), "choice_value", options.TypeStr, "a", "choice", options.WithChoices("a", "b")); err != nil {
					t.Fatal(err)
				}
				o := f.options(t, "choice_value")
				update(t, o, key("enter"))
				s := f.snapshot(t)
				if len(s.Control.Choices) != 2 {
					t.Fatal("missing choices")
				}
				prompt := commander.New(t.Context(), f.bridge)
				prompt.SetSnapshot(s)
				update(t, prompt, key("down"))
				update(t, prompt, key("enter"))
				if got := f.m.Options.Str("choice_value"); got != "b" {
					t.Fatal(got)
				}
			},
			"sequence": func(t *testing.T) {
				f := newFixture(t)
				if err := f.m.Options.Add(t.Context(), "sequence_value", options.TypeSeq, []string{"a", "b"}, "sequence"); err != nil {
					t.Fatal(err)
				}
				o := f.options(t, "sequence_value")
				update(t, o, key("enter"))
				var request *contract.GridRequest
				for len(f.bridge.Control.Mailbox()) > 0 {
					effect := <-f.bridge.Control.Mailbox()
					if effect.Action.Grid != nil {
						request = effect.Action.Grid
					}
				}
				if request == nil {
					t.Fatal("no grid request")
				}
				if diff := gocmp.Diff([][]string{{"a"}, {"b"}}, request.Rows); diff != "" {
					t.Fatal(diff)
				}
				request.Rows[0][0] = "changed"
				option, _ := f.m.Options.Lookup("sequence_value")
				if diff := gocmp.Diff([]string{"a", "b"}, option.Current()); diff != "" {
					t.Fatal("grid aliases option: " + diff)
				}
			},
			"reset": func(t *testing.T) {
				f := newFixture(t)
				if err := f.m.Options.Set(t.Context(), "listen_host=changed"); err != nil {
					t.Fatal(err)
				}
				o := f.options(t, "listen_host")
				update(t, o, key("d"))
				if f.m.Options.HasChanged("listen_host") || o.Error() != nil {
					t.Fatalf("reset: %v", o.Error())
				}
				cmd, _ := o.Update(contract.Action{Kind: "nav", Value: "end"})
				o.Update(contract.Action{Kind: "nav", Value: "start"})
				settle(t, o, cmd)
				state := f.snapshot(t)
				want := slices.Min(f.m.Options.Keys())
				window, _ := state.Control.Current("options", false)
				if o.CurrentName() != want || window.Option != want || window.Index != 0 {
					t.Fatalf("queued option navigation lost: local=%q authoritative=%+v want=%q", o.CurrentName(), window, want)
				}
			},
			"load_save": func(t *testing.T) {
				f := newFixture(t)
				path := filepath.Join(t.TempDir(), "options.yaml")
				if err := f.m.Options.Set(t.Context(), "listen_host=127.0.0.9"); err != nil {
					t.Fatal(err)
				}
				if _, err := f.bridge.Call(t.Context(), "options.save", command.Path(path)); err != nil {
					t.Fatal(err)
				}
				if err := f.m.Options.Set(t.Context(), "listen_host=changed"); err != nil {
					t.Fatal(err)
				}
				if _, err := f.bridge.Call(t.Context(), "options.load", command.Path(path)); err != nil {
					t.Fatal(err)
				}
				if got := f.m.Options.Str("listen_host"); got != "127.0.0.9" {
					t.Fatal(got)
				}
				o := f.options(t, "listen_host")
				update(t, o, key("enter"))
				update(t, o, tea.PasteMsg{Content: "ignored"})
				update(t, o, key("esc"))
				if got := f.m.Options.Str("listen_host"); got != "127.0.0.9" {
					t.Fatal("cancel modified live value")
				}
			},
			"rollback": func(t *testing.T) {
				f := newFixture(t)
				before := f.m.Options.OptInt("listen_port")
				o := f.options(t, "listen_port")
				update(t, o, key("enter"))
				update(t, o, tea.PasteMsg{Content: "invalid"})
				failures := update(t, o, key("enter"))
				if len(failures) != 1 || failures[0].Source != "options" || failures[0].Err == nil {
					t.Fatalf("typed option failure not routed: %+v", failures)
				}
				if o.Error() == nil || !gocmp.Equal(f.m.Options.OptInt("listen_port"), before) {
					t.Fatal("invalid integer was not refused atomically")
				}
				cancel := f.m.Options.Subscribe(func(_ context.Context, updated map[string]struct{}) error {
					if _, ok := updated["showhost"]; ok {
						return options.Errorf("rejected by addon")
					}
					return nil
				})
				defer cancel()
				o = f.options(t, "showhost")
				update(t, o, key("enter"))
				if o.Error() == nil || f.m.Options.Bool("showhost") {
					t.Fatal("addon rejection did not roll back")
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}

func TestConsoleKeybindings(t *testing.T) {
	t.Run("bindings", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"add": func(t *testing.T) {
				f, b := bindingFixture(t)
				update(t, b, key("a"))
				s := f.snapshot(t)
				if len(s.Control.Choices) != len(keymap.Contexts()) || s.Control.Recipe.Command != "console.command" {
					t.Fatal("context selector not prepared")
				}
				if diff := gocmp.Diff([]string{"console.key.bind", "{choice}"}, s.Control.Recipe.Arguments); diff != "" {
					t.Fatal(diff)
				}
			},
			"edit": func(t *testing.T) {
				f, b := bindingFixture(t)
				binding, ok := b.Focused()
				if !ok {
					t.Fatal("missing focus")
				}
				update(t, b, key("enter"))
				s := f.snapshot(t)
				want := commander.CommandPrompt("console.key.bind", strings.Join(binding.Contexts, ","), binding.Key, binding.Command)
				if s.Control.Text != want.Text {
					t.Fatalf("edit prompt %q != %q", s.Control.Text, want.Text)
				}
			},
			"unbind": func(t *testing.T) {
				f, b := bindingFixture(t)
				binding, ok := b.Focused()
				if !ok {
					t.Fatal("missing focus")
				}
				if err := f.m.Commands.Register("console.key.unbind", func(_ context.Context, contexts []string, key string) error {
					return f.bridge.Keys.Remove(key, contexts)
				}, command.WithParams("contexts", "key")); err != nil {
					t.Fatal(err)
				}
				before := len(f.bridge.Keys.Snapshot())
				update(t, b, key("d"))
				if b.Error() != nil {
					t.Fatal(b.Error())
				}
				after := f.bridge.Keys.Snapshot()
				if len(after) >= before {
					t.Fatal("binding not removed")
				}
				for _, item := range after {
					if item.Key == binding.Key && gocmp.Equal(item.Contexts, binding.Contexts) {
						t.Fatal("focused binding survived")
					}
				}
			},
			"execute": func(t *testing.T) {
				f, b := bindingFixture(t)
				binding, _ := b.Focused()
				update(t, b, key("x"))
				s := f.snapshot(t)
				want := commander.CommandPrompt(binding.Command)
				if s.Control.Prompt != "command" || s.Control.Text != want.Text {
					t.Fatal("execute did not open editable prompt")
				}
				if diff := gocmp.Diff(contract.Recipe{}, s.Control.Recipe); diff != "" {
					t.Fatal("execute retained auto-run recipe: " + diff)
				}
			},
			"home_end": func(t *testing.T) {
				f, b := bindingFixture(t)
				update(t, b, contract.Action{Kind: "nav", Value: "end"})
				last, _ := b.Focused()
				all := f.bridge.Keys.Snapshot()
				if diff := gocmp.Diff(all[len(all)-1], last); diff != "" {
					t.Fatal(diff)
				}
				update(t, b, key("home"))
				first, _ := b.Focused()
				if diff := gocmp.Diff(all[0], first); diff != "" {
					t.Fatal(diff)
				}
				update(t, b, key("tab"))
				if _, ok := b.Focused(); ok {
					t.Fatal("help pane exposes a binding")
				}
				update(t, b, key("x"))
				if f.snapshot(t).Control.Prompt != "" {
					t.Fatal("help pane executed a binding")
				}
				window, _ := f.snapshot(t).Control.Current("keybindings", false)
				if window.Binding != "" {
					t.Fatal("help focus retained a binding identity")
				}
				update(t, b, contract.Action{Kind: "nav", Value: "next"})
				cmd, _ := b.Update(contract.Action{Kind: "nav", Value: "end"})
				b.Update(contract.Action{Kind: "nav", Value: "start"})
				b.Update(contract.Action{Kind: "nav", Value: "down"})
				settle(t, b, cmd)
				focused, _ := b.Focused()
				window, _ = f.snapshot(t).Control.Current("keybindings", false)
				if !gocmp.Equal(focused, all[1]) || window.Binding != focused.Key+"@"+strings.Join(focused.Contexts, ",") {
					t.Fatalf("queued binding identity was lost: focused=%+v control=%+v", focused, window)
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}

func bindingFixture(t *testing.T) (fixture, *settings.Bindings) {
	t.Helper()
	f := newFixture(t)
	if err := f.bridge.Dispatch(t.Context(), contract.Action{Kind: "push", Window: contract.Window{Name: "keybindings", Context: "keybindings"}}); err != nil {
		t.Fatal(err)
	}
	b := settings.NewBindings(t.Context(), f.bridge)
	b.SetSnapshot(f.snapshot(t))
	return f, b
}
