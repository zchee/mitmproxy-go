// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package commander_test

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/commandhistory"
	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/master"
)

type fixture struct {
	master *master.Master
	bridge *console.Bridge
	model  *commander.Model
}

func newFixture(t *testing.T, text string) fixture {
	t.Helper()
	m := master.New(master.Config{})
	v := view.New(m.Addons)
	events, err := eventstore.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Add(t.Context(), core.New(m.Addons), commandhistory.New(m.Options), v, events); err != nil {
		t.Fatal(err)
	}
	if err := m.Options.Update(t.Context(), map[string]any{"command_history": false, "confdir": t.TempDir()}); err != nil {
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
	model := commander.New(t.Context(), bridge)
	model.SetSnapshot(contract.Snapshot{Control: contract.State{Prompt: "command", Text: text, Cursor: utf8.RuneCountInString(text)}})
	return fixture{m, bridge, model}
}

func run(t *testing.T, model *commander.Model, msg tea.Msg) {
	t.Helper()
	cmd, _ := model.Update(msg)
	if failures := settle(t, model, cmd); len(failures) > 0 {
		t.Fatalf("unexpected widget failure: %+v", failures)
	}
	if err := model.Error(); err != nil {
		t.Fatal(err)
	}
}

func settle(t *testing.T, widget contract.Widget, cmd tea.Cmd) []contract.ErrorMsg {
	t.Helper()
	pending := []tea.Cmd{cmd}
	var failures []contract.ErrorMsg
	for n := 0; len(pending) > 0; n++ {
		if n > 1000 {
			t.Fatal("command response did not settle")
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

func key(name string) tea.KeyPressMsg {
	keys := map[string]rune{"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight, "backspace": tea.KeyBackspace, "delete": tea.KeyDelete, "tab": tea.KeyTab, "enter": tea.KeyEnter, "esc": tea.KeyEscape, "home": tea.KeyHome, "end": tea.KeyEnd}
	if code, ok := keys[name]; ok {
		return tea.KeyPressMsg{Code: code}
	}
	return tea.KeyPressMsg{Code: []rune(name)[0], Text: name}
}

func textEqual(t *testing.T, model *commander.Model, want string) {
	t.Helper()
	if diff := gocmp.Diff(want, model.Text()); diff != "" {
		t.Fatalf("command line (-want +got):\n%s", diff)
	}
}

func TestConsoleCommander(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("TestListCompleter", func(t *testing.T) {
			t.Run("test_cycle", func(t *testing.T) {
				tests := map[string]struct {
					prefix                           string
					choices, forward, reverse, mixed []string
				}{
					"all":     {"", []string{"c", "a", "b"}, []string{"a", "b", "c", "a"}, []string{"c", "b", "a", "c"}, []string{"a", "c", "a", "c"}},
					"missing": {"xxx", []string{"a", "b", "c"}, []string{"xxx", "xxx", "xxx"}, []string{"xxx", "xxx", "xxx"}, []string{"xxx", "xxx", "xxx"}},
					"prefix":  {"b", []string{"a", "b", "ba", "bb", "c"}, []string{"b", "ba", "bb", "b"}, []string{"bb", "ba", "b", "bb"}, []string{"b", "bb", "b", "bb"}},
				}
				for name, tt := range tests {
					b := commander.NewBuffer(tt.prefix)
					result := contract.Completion{Prefix: tt.prefix, Choices: tt.choices}
					for _, want := range tt.forward {
						b.Complete(result, true)
						if b.Text() != want {
							t.Fatalf("%s forward: %q != %q", name, b.Text(), want)
						}
					}
					for _, want := range tt.reverse {
						b.Complete(result, false)
						if b.Text() != want {
							t.Fatalf("%s reverse: %q != %q", name, b.Text(), want)
						}
					}
					for i, want := range tt.mixed {
						b.Complete(result, i%2 == 0)
						if b.Text() != want {
							t.Fatalf("%s mixed: %q != %q", name, b.Text(), want)
						}
					}
				}
			})
		})
		t.Run("TestCommandEdit", func(t *testing.T) {
			tests := map[string]func(*testing.T){
				"test_open_command_bar": func(t *testing.T) {
					f := newFixture(t, "")
					if !f.model.Active() || f.model.View() != ": " {
						t.Fatalf("empty prompt: %q", f.model.View())
					}
				},
				"test_insert": func(t *testing.T) {
					f := newFixture(t, "")
					run(t, f.model, key(" "))
					textEqual(t, f.model, "")
					run(t, f.model, key("a"))
					textEqual(t, f.model, "a")
				},
				"test_backspace": func(t *testing.T) {
					f := newFixture(t, "")
					run(t, f.model, key("a"))
					run(t, f.model, key("b"))
					textEqual(t, f.model, "ab")
					run(t, f.model, key("backspace"))
					textEqual(t, f.model, "a")
				},
				"test_left": func(t *testing.T) {
					f := newFixture(t, "a")
					if f.model.Cursor() != 1 {
						t.Fatal("initial cursor")
					}
					run(t, f.model, key("left"))
					run(t, f.model, key("left"))
					if f.model.Cursor() != 0 {
						t.Fatal("lower clamp")
					}
				},
				"test_right": func(t *testing.T) {
					f := newFixture(t, "a")
					run(t, f.model, key("right"))
					if f.model.Cursor() != 1 {
						t.Fatal("upper clamp")
					}
					run(t, f.model, key("left"))
					run(t, f.model, key("right"))
					if f.model.Cursor() != 1 {
						t.Fatal("round trip")
					}
				},
				"test_up_and_down": testHistoryTrace,
			}
			for name, test := range tests {
				t.Run(name, test)
			}
		})
		t.Run("TestCommandBuffer", func(t *testing.T) {
			tests := map[string]func(*testing.T){
				"test_backspace": func(t *testing.T) {
					tests := map[string]struct {
						start    string
						cursor   int
						want     string
						position int
					}{"empty": {"", 0, "", 0}, "start_one": {"1", 0, "1", 0}, "end_one": {"1", 1, "", 0}, "end": {"123", 3, "12", 2}, "middle": {"123", 2, "13", 1}, "start": {"123", 0, "123", 0}}
					for name, tt := range tests {
						b := commander.NewBuffer(tt.start)
						b.SetCursor(tt.cursor)
						b.Backspace()
						if b.Text() != tt.want || b.Cursor() != tt.position {
							t.Fatalf("%s: %q/%d", name, b.Text(), b.Cursor())
						}
					}
				},
				"test_left": func(t *testing.T) {
					b := commander.NewBuffer("abcd")
					for _, want := range []int{3, 2, 1, 0, 0} {
						b.Left()
						if b.Cursor() != want {
							t.Fatalf("cursor %d != %d", b.Cursor(), want)
						}
					}
				},
				"test_right": func(t *testing.T) {
					b := commander.NewBuffer("abcd")
					b.SetCursor(0)
					for _, want := range []int{1, 2, 3, 4, 4} {
						b.Right()
						if b.Cursor() != want {
							t.Fatalf("cursor %d != %d", b.Cursor(), want)
						}
					}
				},
				"test_insert": func(t *testing.T) {
					tests := map[string]struct {
						start    string
						cursor   int
						want     string
						position int
					}{"empty": {"", 0, "x", 1}, "front": {"a", 0, "xa", 1}, "end": {"xa", 2, "xax", 3}}
					for name, tt := range tests {
						b := commander.NewBuffer(tt.start)
						b.SetCursor(tt.cursor)
						b.Insert("x")
						if b.Text() != tt.want || b.Cursor() != tt.position {
							t.Fatalf("%s: %q/%d", name, b.Text(), b.Cursor())
						}
					}
				},
				"test_cycle_completion": func(t *testing.T) {
					f := newFixture(t, "foo bar")
					run(t, f.model, key("tab"))
					textEqual(t, f.model, "foo bar")
					f = newFixture(t, "se")
					run(t, f.model, key("tab"))
					textEqual(t, f.model, "set")
					if !strings.Contains(f.model.View(), "option *value ") {
						t.Fatalf("missing registered hints: %q", f.model.View())
					}
				},
				"test_render": func(t *testing.T) {
					f := newFixture(t, "foo")
					run(t, f.model, key("end"))
					if f.model.View() == "" {
						t.Fatal("missing invalid token render")
					}
					f = newFixture(t, "set view_filter '~bq test'")
					run(t, f.model, key("end"))
					if !strings.Contains(f.model.View(), "'~bq test'") {
						t.Fatal(f.model.View())
					}
					f = newFixture(t, "set")
					run(t, f.model, key("end"))
					if !strings.Contains(f.model.View(), "option *value ") {
						t.Fatal(f.model.View())
					}
				},
			}
			for name, test := range tests {
				t.Run(name, test)
			}
		})
	})
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"completion_types": func(t *testing.T) {
				f := newFixture(t, "pick b")
				if err := f.master.Commands.Register("available", func(context.Context) []string { return []string{"beta", "bravo", "alpha"} }); err != nil {
					t.Fatal(err)
				}
				if err := f.master.Commands.Register("pick", func(_ context.Context, _ string) {}, command.WithParams("choice"), command.WithArgument("choice", command.Choice("available"))); err != nil {
					t.Fatal(err)
				}
				run(t, f.model, key("tab"))
				textEqual(t, f.model, "pick beta")
				run(t, f.model, key("tab"))
				textEqual(t, f.model, "pick bravo")
				ref := commander.NewReference(t.Context(), f.bridge)
				ref.SetSnapshot(contract.Snapshot{Commands: []contract.Command{{Name: "z", Signature: "z", Help: "last"}, {Name: "available", Signature: "available", Help: "choices"}}})
				if !strings.Contains(ref.View(), "choices") {
					t.Fatal("reference did not sort owned metadata")
				}
				if err := f.bridge.Dispatch(t.Context(), contract.Action{Kind: "push", Window: contract.Window{Name: "commands", Context: "commands"}}); err != nil {
					t.Fatal(err)
				}
				cmd, _ := ref.Update(contract.Action{Kind: "nav", Value: "end"})
				ref.Update(contract.Action{Kind: "nav", Value: "start"})
				ref.Update(contract.Action{Kind: "nav", Value: "down"})
				ref.Update(contract.Action{Kind: "nav", Value: "select"})
				if failures := settle(t, ref, cmd); len(failures) > 0 {
					t.Fatal(failures)
				}
				var state contract.State
				if err := f.bridge.Do(t.Context(), func(context.Context) error { state = f.bridge.Control.State(); return nil }); err != nil {
					t.Fatal(err)
				}
				if state.Prompt != "command" || state.Text != "z " {
					t.Fatalf("queued reference selection lost: %+v", state)
				}
			},
			"quoted_partial": func(t *testing.T) {
				tests := map[string]struct {
					text          string
					cursor, start int
					choices       []string
					want          string
				}{"open_quote": {"pick 'be", 8, 5, []string{"beta value"}, "pick 'beta value'"}, "middle": {"pick 'be old' tail", 8, 5, []string{"beta value"}, "pick 'beta value' tail"}, "space": {"pick be tail", 7, 5, []string{"beta value"}, "pick \"beta value\" tail"}}
				for name, tt := range tests {
					b := commander.NewBuffer(tt.text)
					b.SetCursor(tt.cursor)
					b.Complete(contract.Completion{Start: tt.start, Prefix: "be", Choices: tt.choices}, true)
					if b.Text() != tt.want {
						t.Fatalf("%s: %q != %q", name, b.Text(), tt.want)
					}
				}
			},
			"unicode_paste": func(t *testing.T) {
				f := newFixture(t, "")
				run(t, f.model, tea.PasteMsg{Content: "echo 日本é👩‍💻"})
				run(t, f.model, key("backspace"))
				textEqual(t, f.model, "echo 日本é")
				run(t, f.model, key("backspace"))
				textEqual(t, f.model, "echo 日本")
				if !utf8.ValidString(f.model.Text()) {
					t.Fatal("broken UTF-8")
				}
			},
			"cancel_prompt": func(t *testing.T) {
				f := newFixture(t, "")
				calls := 0
				if err := f.master.Commands.Register("chosen", func(_ context.Context, a, b string) {
					calls++
					if a != "x/x" || b != "y:x" {
						t.Fatalf("replacements: %q %q", a, b)
					}
				}, command.WithParams("a", "b")); err != nil {
					t.Fatal(err)
				}
				a := commander.ChoicePrompt("Choose", []string{"x"}, "chosen", []string{"{choice}/{choice}", "y:{choice}"})
				s := contract.State{Prompt: a.Value, Text: a.Text, Choices: a.Choices, Recipe: a.Recipe}
				f.model.SetSnapshot(contract.Snapshot{Control: s})
				run(t, f.model, key("esc"))
				if calls != 0 {
					t.Fatal("cancel executed")
				}
				f.model.SetSnapshot(contract.Snapshot{})
				f.model.SetSnapshot(contract.Snapshot{Control: s})
				run(t, f.model, key("enter"))
				if calls != 1 {
					t.Fatal("choice not executed")
				}
				a = commander.ConfirmPrompt("Confirm", "chosen", []string{"x/x", "y:x"})
				f.model.SetSnapshot(contract.Snapshot{Control: contract.State{Prompt: a.Value, Text: a.Text, Choices: a.Choices, Recipe: a.Recipe}})
				run(t, f.model, key("n"))
				if calls != 1 {
					t.Fatal("declined confirmation executed")
				}
			},
			"history": func(t *testing.T) {
				f := newFixture(t, "set view_filter test")
				run(t, f.model, key("enter"))
				value, err := f.bridge.Call(t.Context(), "commands.history.get")
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff([]string{"set view_filter test"}, value); diff != "" {
					t.Fatal(diff)
				}
				if f.model.Active() {
					t.Fatal("enter left prompt active")
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}

func testHistoryTrace(t *testing.T) {
	f := newFixture(t, "")
	type action struct{ key, want string }
	trace := []action{
		{"clear", ""},
		{"add:cmd1", ""},
		{"up", "cmd1"},
		{"up", "cmd1"},
		{"down", ""},
		{"down", ""},
		{"new", ""},
		{"clear", ""},
		{"add:cmd1", ""},
		{"add:cmd2", ""},
		{"up", "cmd2"},
		{"up", "cmd1"},
		{"up", "cmd1"},
		{"down", "cmd2"},
		{"down", ""},
		{"a", "a"},
		{"b", "ab"},
		{"c", "abc"},
		{"up", "abc"},
		{"down", "abc"},
		{"down", "abc"},
		{"up", "abc"},
		{"new", ""},
		{"add:cmd3", ""},
		{"z", "z"},
		{"up", "z"},
		{"down", "z"},
		{"down", "z"},
		{"backspace", ""},
		{"up", "cmd3"},
		{"up", "cmd2"},
		{"up", "cmd1"},
		{"down", "cmd2"},
		{"down", "cmd3"},
		{"down", ""},
		{"c", "c"},
		{"down", ""},
		{"up", "cmd3"},
		{"down", ""},
		{"up", "cmd3"},
		{"up", "cmd2"},
		{"down", "cmd3"},
		{"down", ""},
		{"down", ""},
		{"up", "cmd3"},
		{"up", "cmd2"},
		{"up", "cmd1"},
		{"up", "cmd1"},
		{"up", "cmd1"},
		{"down", "cmd2"},
		{"down", "cmd3"},
		{"down", ""},
		{"down", ""},
		{"backspace", ""},
		{"up", "cmd3"},
		{"up", "cmd2"},
		{"up", "cmd1"},
		{"down", "cmd2"},
		{"down", "cmd3"},
		{"down", ""},
	}
	for i, a := range trace {
		switch {
		case a.key == "new":
			f.model = commander.New(t.Context(), f.bridge)
			f.model.SetSnapshot(contract.Snapshot{Control: contract.State{Prompt: "command"}})
		case a.key == "clear":
			if _, err := f.bridge.Call(t.Context(), "commands.history.clear"); err != nil {
				t.Fatal(err)
			}
		case strings.HasPrefix(a.key, "add:"):
			if _, err := f.bridge.Call(t.Context(), "commands.history.add", strings.TrimPrefix(a.key, "add:")); err != nil {
				t.Fatal(err)
			}
		default:
			run(t, f.model, key(a.key))
		}
		if diff := gocmp.Diff(a.want, f.model.Text()); diff != "" {
			t.Fatalf("action %d (%s): %s", i, a.key, diff)
		}
	}
}
