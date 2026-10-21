// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func TestConsoleCommands(t *testing.T) {
	t.Run("commands", func(t *testing.T) {
		tests := map[string]struct{ args []string }{
			"console.bodyview": {[]string{"@focus", "request"}}, "console.bodyview.options": {},
			"console.edit.focus.options": {}, "console.edit.focus": {[]string{"request-headers"}},
			"console.grideditor.add": {}, "console.grideditor.insert": {}, "console.grideditor.delete": {},
			"console.grideditor.load": {[]string{"operator.txt"}}, "console.grideditor.load_escaped": {[]string{"operator.txt"}},
			"console.grideditor.save": {[]string{"operator.csv"}}, "console.grideditor.editor": {},
			"console.layout.options": {}, "console.layout.cycle": {},
			"console.panes.next": {}, "console.panes.prev": {},
			"console.options.reset.focus": {},
			"console.nav.start":           {}, "console.nav.end": {}, "console.nav.next": {}, "console.nav.select": {},
			"console.nav.up": {}, "console.nav.down": {}, "console.nav.pageup": {}, "console.nav.pagedown": {},
			"console.nav.left": {}, "console.nav.right": {},
			"console.choose":           {[]string{"Choose", "single,vertical,horizontal", "set", "console_layout", "{choice}"}},
			"console.choose.cmd":       {[]string{"Choose", "console.layout.options", "set", "console_layout", "{choice}"}},
			"console.command":          {[]string{"set", "console_layout"}},
			"console.command.confirm":  {[]string{"Continue", "set", "console_layout", "vertical"}},
			"console.command.set":      {[]string{"console_layout"}},
			"console.view.keybindings": {}, "console.view.commands": {}, "console.view.options": {},
			"console.view.eventlog": {}, "console.view.help": {}, "console.view.flow": {[]string{"@focus"}},
			"console.exit": {}, "console.view.pop": {},
			"console.flowview.mode.set": {[]string{"raw"}}, "console.flowview.mode.options": {}, "console.flowview.mode": {},
			"console.key.contexts":     {},
			"console.key.bind":         {[]string{"global", "ctrl a", "console.nav.start"}},
			"console.key.unbind":       {[]string{"global", "ctrl a"}},
			"console.key.unbind.focus": {}, "console.key.execute.focus": {}, "console.key.edit.focus": {},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				b, _ := testBridge(t)
				mustConsole(t, b.cfg.Master.Addons.Add(t.Context(), core.New(b.cfg.Master.Addons), &ConsoleAddon{bridge: b}))
				verifyCommandMetadata(t, b, name)
				ctx, finish := BeginInvocation(t.Context())
				var result any
				mustConsole(t, b.Do(ctx, func(ctx context.Context) error {
					f := testflow.TFlow()
					b.cfg.View.Add(ctx, []flow.Flow{f})
					if strings.HasPrefix(name, "console.flowview.mode") {
						if _, err := b.cfg.Master.Call(ctx, "console.view.flow", f); err != nil {
							return err
						}
					}
					if name == "console.options.reset.focus" {
						if _, err := b.cfg.Master.Call(ctx, "console.view.options"); err != nil {
							return err
						}
						if err := b.Dispatch(ctx, contract.Action{Kind: "option", Value: "showhost"}); err != nil {
							return err
						}
						if err := b.cfg.Master.Options.Update(ctx, map[string]any{"showhost": true}); err != nil {
							return err
						}
					}
					if strings.HasSuffix(name, ".focus") && strings.HasPrefix(name, "console.key.") {
						if _, err := b.cfg.Master.Call(ctx, "console.view.keybindings"); err != nil {
							return err
						}
					}
					if strings.HasPrefix(name, "console.grideditor.") {
						if _, err := b.cfg.Master.Commands.CallStrings(ctx, "console.edit.focus", []string{"request-headers"}); err != nil {
							return err
						}
					}
					if name == "console.key.unbind" {
						if _, err := b.cfg.Master.Commands.CallStrings(ctx, "console.key.bind", []string{"global", "ctrl a", "console.nav.start"}); err != nil {
							return err
						}
					}
					var err error
					result, err = b.cfg.Master.Commands.CallStrings(ctx, name, test.args)
					return err
				}))
				batch := finish()
				state := b.Control.State()
				current, _ := state.Current("", true)
				switch {
				case name == "console.bodyview":
					if len(batch) != 1 || batch[0].Action.Kind != "external" || batch[0].Action.Value != "view" || batch[0].Action.Target == nil || batch[0].Action.Target.Part != "request-body" {
						t.Fatalf("viewer target: %+v", batch)
					}
				case name == "console.bodyview.options":
					if diff := cmp.Diff([]string{"request", "response"}, result); diff != "" {
						t.Fatal(diff)
					}
				case name == "console.edit.focus.options":
					values, ok := result.([]string)
					if !ok || !slices.Contains(values, "request-headers") || values[len(values)-1] != "comment" {
						t.Fatalf("edit choices: %v", result)
					}
				case name == "console.edit.focus":
					if len(batch) != 1 || batch[0].Action.Grid == nil || batch[0].Action.Grid.Flow == nil || batch[0].Action.Grid.Target.Part != "request-headers" || current.Context != "grideditor" {
						t.Fatalf("detached grid payload: %+v", batch)
					}
				case strings.HasPrefix(name, "console.grideditor."):
					if len(batch) != 2 || batch[1].Action.Kind != "grid" || batch[1].Action.Value != strings.TrimPrefix(name, "console.grideditor.") {
						t.Fatalf("grid operation ordering: %+v", batch)
					}
				case name == "console.layout.options":
					if diff := cmp.Diff([]string{"single", "vertical", "horizontal"}, result); diff != "" {
						t.Fatal(diff)
					}
				case name == "console.layout.cycle":
					if state.Layout != "vertical" || b.cfg.Master.Options.Str("console_layout") != "vertical" || len(batch) != 2 {
						t.Fatal("layout cycle did not sequence option-derived panes")
					}
				case name == "console.options.reset.focus":
					if b.cfg.Master.Options.Bool("showhost") {
						t.Fatal("same-Do focused option reset was not visible")
					}
				case strings.HasPrefix(name, "console.nav."):
					if len(batch) != 1 || batch[0].Action.Kind != "nav" || batch[0].Action.Value != strings.TrimPrefix(name, "console.nav.") {
						t.Fatalf("navigation effect: %+v", batch)
					}
				case name == "console.choose" || name == "console.choose.cmd":
					if state.Prompt != "choice" || len(state.Choices) != 3 {
						t.Fatalf("choice prompt: %+v", state)
					}
					mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error { _, err := b.Resolve(ctx, state.Recipe, "vertical"); return err }))
					if b.cfg.Master.Options.Str("console_layout") != "vertical" {
						t.Fatal("detached choice recipe did not execute")
					}
				case name == "console.command" || name == "console.key.execute.focus" || name == "console.key.edit.focus":
					if state.Prompt != "command" || state.Text == "" || !strings.HasSuffix(state.Text, " ") {
						t.Fatalf("command prompt: %+v", state)
					}
				case name == "console.command.confirm":
					if state.Prompt != "confirm" || state.Recipe.Command != "set" || b.cfg.Master.Options.Str("console_layout") != "single" {
						t.Fatal("confirmation executed before approval")
					}
				case name == "console.command.set":
					if state.Text != "set console_layout 'single'" || state.Cursor != len(state.Text)-1 {
						t.Fatalf("option prompt: %+v", state)
					}
				case strings.HasPrefix(name, "console.view.") && name != "console.view.pop":
					wanted := strings.TrimPrefix(name, "console.view.")
					if wanted == "flow" {
						wanted = "flowview"
					}
					if current.Context != wanted {
						t.Fatalf("view context=%q, want %q", current.Context, wanted)
					}
				case name == "console.view.pop":
					if !state.QuitPrompt {
						t.Fatal("base pop did not request exit confirmation")
					}
				case name == "console.flowview.mode.set":
					value, err := b.Call(t.Context(), "console.flowview.mode")
					mustConsole(t, err)
					if value != "raw" {
						t.Fatalf("mode=%v, want raw", value)
					}
				case name == "console.flowview.mode":
					if result != "auto" {
						t.Fatalf("mode=%v, want default auto", result)
					}
				case name == "console.flowview.mode.options":
					if diff := cmp.Diff(b.cfg.Registry.AvailableViews(), result); diff != "" {
						t.Fatal(diff)
					}
				case name == "console.key.contexts":
					if diff := cmp.Diff([]string{"chooser", "commands", "commonkey", "dataviewer", "eventlog", "flowlist", "flowview", "global", "grideditor", "help", "keybindings", "options"}, result); diff != "" {
						t.Fatal(diff)
					}
				case name == "console.key.bind" || name == "console.key.unbind":
					_, exists := b.Keys.Get("global", "ctrl a")
					if exists != (name == "console.key.bind") {
						t.Fatal("binding mutation not visible under dispatch")
					}
				case name == "console.key.unbind.focus":
					if _, err := b.binding(current.Binding); err == nil {
						t.Fatal("focused binding still exists after unbind")
					}
				}
				if name == "console.choose" || name == "console.choose.cmd" || name == "console.command.confirm" {
					m := NewModel(b, map[string]WidgetFactory{"commander": func(host contract.Host) contract.Widget { return commander.New(t.Context(), host) }})
					m.state = state.Clone()
					want := tea.NewCursor(6, 20)
					if name == "console.command.confirm" {
						want = tea.NewCursor(8, 21)
					}
					for _, layout := range []string{"single", "vertical", "horizontal"} {
						m.state.Layout = layout
						m.refreshWidgets()
						if diff := cmp.Diff(want, m.View().Cursor); diff != "" {
							t.Fatalf("%s %s caption cursor (-want +got): %s", name, layout, diff)
						}
					}
				}
				NewInstaller(b.Control).Install(batch)
				if name == "console.options.reset.focus" || name == "console.flowview.mode" || strings.HasSuffix(name, ".focus") && strings.HasPrefix(name, "console.key.") {
					other, _ := testBridge(t)
					mustConsole(t, other.cfg.Master.Addons.Add(t.Context(), core.New(other.cfg.Master.Addons), &ConsoleAddon{bridge: other}))
					if _, err := other.Call(t.Context(), name); err == nil {
						t.Fatal("context-specific command succeeded in an unrelated master")
					}
				}
			})
		}
	})
}

func verifyCommandMetadata(t *testing.T, b *Bridge, name string) {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/mitmproxy/tools/console/consoleaddons.py")
	mustConsole(t, err)
	pattern := regexp.MustCompile(`(?s)@command.command\("` + regexp.QuoteMeta(name) + `"\).*?\n    def [^(]+\((.*?)\) -> ([^:\n]+):\s*"""(.*?)"""`)
	match := pattern.FindStringSubmatch(string(data))
	if match == nil {
		t.Fatalf("missing pinned-source metadata for %s", name)
	}
	var registered *command.Command
	for _, candidate := range b.cfg.Master.Commands.Commands() {
		if candidate.Name == name {
			registered = candidate
			break
		}
	}
	if registered == nil {
		t.Fatalf("missing command: %s", name)
	}
	if want, got := strings.Join(strings.Fields(match[3]), " "), strings.Join(strings.Fields(registered.Help), " "); got != want {
		t.Fatalf("help=%q, want pinned source %q", got, want)
	}
	var expected []command.Param
	for parameter := range strings.SplitSeq(match[1], ",") {
		parameter = strings.TrimSpace(parameter)
		if parameter == "self" || parameter == "" {
			continue
		}
		key, annotation, ok := strings.Cut(parameter, ":")
		if !ok {
			t.Fatalf("unrecognized pinned parameter: %q", parameter)
		}
		param := command.Param{Name: strings.TrimPrefix(strings.TrimSpace(key), "*"), Variadic: strings.HasPrefix(key, "*")}
		switch strings.TrimSpace(annotation) {
		case "str":
			param.Type = command.StrType
		case "Sequence[str]":
			param.Type = command.StrSeqType
		case "flow.Flow":
			param.Type = command.FlowType
		case "mitmproxy.types.Cmd":
			param.Type = command.CmdType
		case "mitmproxy.types.CmdArgs":
			param.Type = command.ArgType
		case "mitmproxy.types.Path":
			param.Type = command.PathType
		default:
			t.Fatalf("unrecognized pinned annotation: %q", annotation)
		}
		if name == "console.bodyview" && param.Name == "part" {
			param.Type = command.Choice("console.bodyview.options")
		}
		if name == "console.edit.focus" && param.Name == "flow_part" {
			param.Type = command.Choice("console.edit.focus.options")
		}
		if name == "console.flowview.mode.set" && param.Name == "mode" {
			param.Type = command.Choice("console.flowview.mode.options")
		}
		expected = append(expected, param)
	}
	if len(expected) != len(registered.Params) {
		t.Fatalf("params=%+v, want %+v", registered.Params, expected)
	}
	for i, param := range expected {
		if param != registered.Params[i] {
			t.Fatalf("parameter %d=%+v, want %+v", i, registered.Params[i], param)
		}
	}
	var returns command.Type
	switch strings.TrimSpace(match[2]) {
	case "None":
	case "str":
		returns = command.StrType
	case "Sequence[str]":
		returns = command.StrSeqType
	default:
		t.Fatalf("unrecognized pinned return: %q", match[2])
	}
	if returns != registered.Return {
		t.Fatalf("return=%v, want %v", registered.Return, returns)
	}
	if slices.ContainsFunc(registered.Params, func(p command.Param) bool { return p.Name == "" }) {
		t.Fatal("unnamed command parameter")
	}
}
