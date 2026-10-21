// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	teatest "github.com/charmbracelet/x/exp/teatest/v2"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
	"github.com/zchee/mitmproxy-go/options"
)

type resizeModel struct {
	model *Model
	sizes chan tea.WindowSizeMsg
}

func (m *resizeModel) Init() tea.Cmd  { return m.model.Init() }
func (m *resizeModel) View() tea.View { return m.model.View() }
func (m *resizeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	_, cmd := m.model.Update(msg)
	if _, ok := msg.(tea.WindowSizeMsg); ok {
		m.sizes <- tea.WindowSizeMsg{Width: m.model.width, Height: m.model.height}
	}
	return m, cmd
}

func TestConsoleWindow(t *testing.T) {
	tests := map[string]struct{}{"single": {}, "vertical": {}, "horizontal": {}, "overlay_stack": {}, "resize": {}, "mouse_offsets": {}}
	t.Run("layout", func(t *testing.T) {
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				state := contract.NewState()
				switch name {
				case "single", "vertical", "horizontal":
					state.Layout = name
					rects := Layout(state, 80, 24, 3)
					want := 1
					if name != "single" {
						want = 2
					}
					if len(rects) != want {
						t.Fatalf("pane count %d != %d", len(rects), want)
					}
					for _, r := range rects {
						if r.Width < 0 || r.Height < 0 || r.Y+r.Height > 21 {
							t.Fatalf("invalid rectangle %+v", r)
						}
					}
					frame := Compose(state, []string{"left", "right"}, 80, 24, []string{"status", "top", "bottom"})
					if len(strings.Split(frame, "\n")) != 24 {
						t.Fatal("wrong frame height")
					}
					for line := range strings.SplitSeq(frame, "\n") {
						if style.Width(line) != 80 {
							t.Fatal("wrong frame width")
						}
					}
					m := NewModel(nil, nil)
					m.state = state
					frame = m.View().Content
					for i, rect := range rects {
						tag := "heading_inactive"
						if i == state.Pane {
							tag = "heading"
						}
						title := []string{"Flows", "Events"}[i]
						if !strings.Contains(frame, m.palette.Style(tag).Render(style.Fit(title, rect.Width))) {
							t.Fatalf("%s pane %d missing %s header styling: %q", name, i, tag, strings.Split(frame, "\n")[rect.Y-1])
						}
					}
					if name == "single" {
						b, _ := testBridge(t)
						mustConsole(t, b.cfg.Master.Addons.Add(t.Context(), &ConsoleAddon{bridge: b}))
						f := testflow.TFlow()
						mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error { b.cfg.View.Add(ctx, []flow.Flow{f}); return nil }))
						views := map[string]struct{ title string }{
							"flow": {"Flow Details"}, "eventlog": {"Events"}, "options": {"Options"},
							"help": {"Help"}, "commands": {"Command Reference"}, "keybindings": {"Key Bindings"},
						}
						for view, tt := range views {
							var args []any
							if view == "flow" {
								args = []any{f}
							}
							_, err := b.Call(t.Context(), "console.view."+view, args...)
							mustConsole(t, err)
							current := b.Control.State()
							if got, _, _ := strings.Cut(Compose(current, nil, 80, 24, nil), "\n"); got != style.Fit(tt.title, 80) {
								t.Fatalf("%s display title (-want +got): %s", view, cmp.Diff(style.Fit(tt.title, 80), got))
							}
						}
						editors := map[string]struct{ title string }{
							"query": {"Edit Query"}, "request-headers": {"Edit Request Headers"}, "response-headers": {"Edit Response Headers"},
							"multipart form": {"Edit Multipart Form"}, "urlencoded form": {"Edit UrlEncoded Form"}, "path": {"Edit Path Components"},
							"comment": {"Edit Comment"}, "cookies": {"Edit Cookies"}, "set-cookies": {"Edit SetCookie Header"},
						}
						for part, tt := range editors {
							_, err := b.Call(t.Context(), "console.edit.focus", part)
							mustConsole(t, err)
							window, _ := b.Control.State().Current("grideditor", false)
							if diff := cmp.Diff(tt.title, window.Title); diff != "" {
								t.Fatalf("%s editor title (-want +got): %s", part, diff)
							}
						}
						mustConsole(t, b.OpenGrid(t.Context(), contract.GridRequest{Title: "column label", Option: "option"}))
						window, _ := b.Control.State().Current("grideditor", false)
						if window.Title != "" {
							t.Fatal("sequence column label became a pane title")
						}
					}
				case "overlay_stack":
					var err error
					state, err = reduce(state, contract.Action{Kind: "push", Window: contract.Window{Name: "options", Title: "Options", Context: "options"}})
					mustConsole(t, err)
					state, err = reduce(state, contract.Action{Kind: "overlay", Window: contract.Window{Name: "chooser", Context: "chooser"}})
					mustConsole(t, err)
					if _, ok := state.Current("options", true); ok {
						t.Fatal("overlay did not hide current widget")
					}
					if _, ok := state.Current("options", false); !ok {
						t.Fatal("overlay hid current window")
					}
					frame := Compose(state, nil, 80, 24, nil)
					if !strings.HasPrefix(frame, style.Fit("Options", 80)+"\n") {
						t.Fatal("overlay changed the underlying pane title")
					}
					state.Panes[0].Stack[1].Title = "Editor\x1b]52;c;payload\a"
					frame = Compose(state, nil, 80, 24, nil)
					if strings.ContainsAny(frame, "\x1b\a") || !strings.HasPrefix(frame, style.Fit(style.Escape("Editor\x1b]52;c;payload\a"), 80)) {
						t.Fatal("pane title leaked terminal controls")
					}
					state, err = reduce(state, contract.Action{Kind: "pop"})
					mustConsole(t, err)
					w, _ := state.Current("", true)
					if w.Context != "options" {
						t.Fatal("pop did not restore underlying view")
					}
					state, err = reduce(state, contract.Action{Kind: "pop"})
					mustConsole(t, err)
					state, err = reduce(state, contract.Action{Kind: "pop"})
					mustConsole(t, err)
					if !state.QuitPrompt {
						t.Fatal("root pop skipped confirmation")
					}
				case "resize":
					m := NewModel(nil, map[string]WidgetFactory{"flowlist": func(contract.Host) contract.Widget { return NewHelpWidget("flowlist") }})
					wrapped := &resizeModel{model: m, sizes: make(chan tea.WindowSizeMsg, 2)}
					tm := teatest.NewTestModel(t, wrapped, teatest.WithInitialTermSize(80, 24))
					t.Cleanup(func() {
						mustConsole(t, tm.Quit())
						tm.WaitFinished(t, teatest.WithFinalTimeout(5*time.Second))
					})
					// Teatest and the program each deliver their own initial size.
					for i, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 80, Height: 24}, {Width: 200, Height: 50}} {
						if i == 2 {
							tm.Send(size)
						}
						select {
						case installed := <-wrapped.sizes:
							if diff := cmp.Diff(size, installed); diff != "" {
								t.Fatal("installed resize mismatch (-want +got): " + diff)
							}
						case <-time.After(5 * time.Second):
							t.Fatal("resize was not installed before watchdog")
						}
					}
					mustConsole(t, tm.Quit())
					final := tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(*resizeModel).model
					if final.width != 200 || final.height != 50 {
						t.Fatal("resize lost")
					}
					if len(strings.Split(final.View().Content, "\n")) != 50 {
						t.Fatal("resized frame height wrong")
					}
					final.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
					if final.width != 80 || final.height != 24 {
						t.Fatal("later delivered smaller size was ignored")
					}
				case "mouse_offsets":
					state.Layout = "vertical"
					rects := Layout(state, 80, 24, 3)
					p, col, row, ok := Hit(rects, 4, rects[1].Y+2, [2]int{0, 400})
					if !ok || p != 1 || col != 4 || row != 402 {
						t.Fatalf("hit=%d,%d,%d,%v", p, col, row, ok)
					}
					if _, _, _, ok := Hit(rects, 4, 23, [2]int{}); ok {
						t.Fatal("footer selected a row")
					}
					state.Mouse = false
					m := NewModel(nil, nil)
					m.state = state
					if m.View().MouseMode != tea.MouseModeNone {
						t.Fatal("disabled mouse requested mouse mode")
					}
					tests := map[string]struct {
						prompt, text, layout string
						width, height, index int
						commander            bool
						want                 *tea.Cursor
					}{
						"commander home":      {"command", "abc", "single", 80, 24, 0, true, tea.NewCursor(2, 22)},
						"commander middle":    {"command", "ab界z", "single", 80, 24, 3, true, tea.NewCursor(6, 22)},
						"commander end":       {"command", "console.view.flow ", "single", 200, 50, 18, true, tea.NewCursor(20, 48)},
						"commander combining": {"command", "界éz", "single", 80, 24, 3, true, tea.NewCursor(5, 22)},
						"text input":          {"text", "界éz", "single", 80, 24, 3, false, tea.NewCursor(7, 22)},
						"onekey input":        {"onekey", "", "single", 80, 24, 0, false, tea.NewCursor(4, 22)},
						"narrow":              {"text", "abc", "single", 1, 24, 3, false, tea.NewCursor(0, 22)},
						"zero width":          {"command", "abc", "single", 0, 24, 3, true, nil},
						"zero height":         {"command", "abc", "single", 80, 0, 3, true, nil},
						"choice menu":         {"choice", "abc", "single", 80, 24, 0, false, tea.NewCursor(3, 22)},
						"confirmation menu":   {"confirm", "Quit (yes,no)? ", "single", 80, 24, 0, false, tea.NewCursor(15, 22)},
						"commander choice":    {"choice", "選択 (y,n)? ", "single", 80, 24, 0, true, tea.NewCursor(12, 22)},
						"commander confirm":   {"confirm", "Quit (yes,no)? ", "single", 80, 24, 0, true, tea.NewCursor(15, 22)},
						"narrow menu":         {"choice", "abc", "single", 2, 24, 0, false, tea.NewCursor(1, 22)},
					}
					for name, tt := range tests {
						m := NewModel(nil, nil)
						m.width, m.height = tt.width, tt.height
						m.state.Layout = tt.layout
						m.state.Prompt, m.state.Text, m.state.Cursor = tt.prompt, tt.text, tt.index
						if tt.prompt == "choice" || tt.prompt == "confirm" {
							m.state.Choices = []contract.Choice{{Label: "yes", Value: "y"}}
						}
						m.input.SetValue(tt.text)
						m.input.SetCursor(tt.index)
						if tt.commander {
							m.factories = map[string]WidgetFactory{"commander": func(host contract.Host) contract.Widget { return commander.New(t.Context(), host) }}
						}
						m.refreshWidgets()
						if diff := cmp.Diff(tt.want, m.View().Cursor); diff != "" {
							t.Fatalf("%s cursor (-want +got): %s", name, diff)
						}
						if tt.commander && len(m.state.Choices) > 0 {
							m.state.Choices = append(m.state.Choices, contract.Choice{Label: "no", Value: "n"}, contract.Choice{Label: "cancel", Value: "q"})
							m.refreshWidgets()
							if diff := cmp.Diff(tea.NewCursor(tt.want.X, 20), m.View().Cursor); diff != "" {
								t.Fatalf("%s expanded menu cursor (-want +got): %s", name, diff)
							}
						}
						m.state.Prompt = ""
						if m.View().Cursor != nil {
							t.Fatalf("%s retained cursor after prompt closed", name)
						}
					}
				}
			})
		}
	})
}

func TestConsoleQuickHelp(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("test_quickhelp", func(t *testing.T) {
			tests := map[string]struct {
				context                  string
				focused, nested, overlay bool
				want                     string
			}{
				"flowlist_empty": {"flowlist", false, false, false, "Load flows"}, "flowlist_focused": {"flowlist", true, false, false, "Select"}, "flowview_intercepted_marked_modified": {"flowview", true, false, false, "Edit"}, "keybindings_root": {"keybindings", false, false, false, "Keybindings:"}, "options_root": {"options", false, false, false, "Options:"}, "help_nested": {"help", false, true, false, "Help:"}, "eventlog_root": {"eventlog", false, false, false, "Events:"}, "path_editor": {"grideditor", false, false, false, "Edit:"}, "overlay": {"chooser", false, false, true, "Proxy:"},
			}
			for name, tt := range tests {
				t.Run(name, func(t *testing.T) {
					state := contract.NewState()
					state.Panes[0].Stack = []contract.Window{{Name: tt.context, Context: tt.context}}
					if tt.nested {
						state.Panes[0].Stack = append([]contract.Window{{Name: "flowlist", Context: "flowlist"}}, state.Panes[0].Stack...)
					}
					if tt.overlay {
						state.Panes[0].Overlay = &contract.Window{Name: "choice", Context: "chooser"}
					}
					keys := keymap.NewDefault(nil)
					snapshot := contract.Snapshot{Bindings: keys.Snapshot(), HelpBindings: keys.HelpSnapshot()}
					if tt.focused {
						f := testflow.TFlow()
						f.Backup()
						f.Request.Method = "PATCH"
						f.Marked = "*"
						f.Intercept()
						snapshot.Focused = f
					}
					rows := QuickHelp(state, snapshot, 300)
					if !strings.Contains(rows[0]+rows[1], tt.want) {
						t.Fatalf("missing %q: %q", tt.want, rows)
					}
					if tt.nested && !strings.Contains(rows[1], "q Back") {
						t.Fatal("nested help lost Back")
					}
				})
			}
		})
		t.Run("test_make_rows", func(t *testing.T) {
			items := []helpItem{{short: "bound", help: "Select"}, {short: "unbound", help: "missing"}, {short: "basic", key: "↓"}}
			keys := keymap.NewDefault(nil)
			b, _ := testBridge(t)
			snapshot, err := b.capture(b.generation.Load())
			mustConsole(t, err)
			copy := snapshot.Clone()
			copy.HelpBindings[0].Contexts[0] = "changed"
			if snapshot.HelpBindings[0].Contexts[0] == "changed" {
				t.Fatal("help bindings share mutable contexts across snapshots")
			}
			rows := QuickHelp(contract.NewState(), snapshot, 80)
			// Pinned quickhelp.py fixed columns and the sealed upstream 80-column frame.
			want := "Proxy:   ? Help        q Quit        E Events      O Options     i Intercept    "
			if diff := cmp.Diff(want, rows[1]); diff != "" {
				t.Fatal("upstream proxy help (-want +got): " + diff)
			}
			widths := map[string]struct {
				width int
				want  string
			}{
				"empty": {0, ""}, "label clipped": {3, "tes"}, "no item fits": {22, "test" + strings.Repeat(" ", 18)},
				"one item fits": {23, "test     ⏎ bound       "}, "second item omitted": {36, "test     ⏎ bound" + strings.Repeat(" ", 20)},
				"two items fit": {37, "test     ⏎ bound       ↓ basic       "},
			}
			for name, tt := range widths {
				if diff := cmp.Diff(tt.want, helpRow("test", items, keys.HelpSnapshot(), 9, tt.width)); diff != "" {
					t.Fatalf("%s whole-column clipping (-want +got): %s", name, diff)
				}
			}
			long := helpRow("test", []helpItem{{short: "abcdefghijklmnop", key: "x"}}, nil, 9, 23)
			if diff := cmp.Diff("test     x abcdefghijkl", long); diff != "" {
				t.Fatal("cell must clip without ellipsis (-want +got): " + diff)
			}
			row := helpRow("test", items, keys.HelpSnapshot(), 9, 80)
			if !strings.Contains(row, "⏎ bound") || !strings.Contains(row, "↓ basic") || strings.Contains(row, "unbound") {
				t.Fatalf("wrong help resolution: %q", row)
			}
		})
	})
}

func TestConsoleStatusBar(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("test_shorten_message", func(t *testing.T) {
			tests := map[string]struct{ message, want string }{"empty": {"", ""}, "info_fits": {"Line fits into statusbar", "Line fits into statusbar"}, "long_line": {"Line doesn't fit into statusbar", "Line doesn'…(more in eventlog)"}, "alert_multiline": {"Two lines.\nFirst fits", "Two lines.(more in eventlog)"}, "multiline_long": {"Two long lines\nFirst doesn't fit", "Two long li…(more in eventlog)"}}
			for name, tt := range tests {
				t.Run(name, func(t *testing.T) {
					if diff := cmp.Diff(tt.want, ShortenMessage(tt.message, 30)); diff != "" {
						t.Fatal(diff)
					}
				})
			}
		})
		tests := map[string]struct{}{"test_statusbar": {}, "test_shorten_message_narrow": {}, "test_console_quickhelp_option": {}, "test_console_quickhelp_toggle": {}, "test_console_quickhelp_hotkey": {}, "test_console_quickhelp_prompts_visible_when_disabled": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				b, _ := testBridge(t)
				m := NewModel(b, nil)
				mustConsole(t, b.cfg.Master.Options.Add(t.Context(), "console_quickhelp_visible", options.TypeBool, true, "Show quick help."))
				refresh := func() {
					s, err := b.capture(b.generation.Load())
					mustConsole(t, err)
					m.Update(contract.SnapshotMsg{Snapshot: s})
				}
				refresh()
				switch name {
				case "test_statusbar":
					for _, level := range []slog.Level{slog.LevelWarn, slog.LevelError, addon.LevelAlert} {
						mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
							return b.cfg.Events.Add(ctx, addon.LogEntry{Msg: "new event", Level: level})
						}))
						refresh()
						if m.message != "new event" {
							t.Fatal("new warning/error/alert not routed to status")
						}
						m.message = "user message"
						refresh()
						if m.message != "user message" {
							t.Fatal("retained event overwrote later status")
						}
					}
					mustConsole(t, b.cfg.Master.Options.Add(t.Context(), "console_palette", options.TypeStr, "dark", "Palette."))
					mustConsole(t, b.cfg.Master.Options.Add(t.Context(), "console_palette_transparent", options.TypeBool, false, "Transparency."))
					refresh()
					if m.palette.Name != "dark" || m.palette.Transparent {
						t.Fatal("configured palette not applied")
					}
					<-b.installed
					m.Update(contract.ErrorMsg{Source: "widget", Err: errors.New("bad\x1b]52;c;payload\a")})
					if len(b.installed) != 0 || m.snapshot.Generation == 0 || strings.ContainsAny(strings.Join(m.footer(), "\n"), "\x1b\a") {
						t.Fatal("widget failure acknowledged a snapshot or leaked terminal controls")
					}
					m.message = ""
					m.snapshot.Status = contract.Status{Reverse: true, Marked: true, Indicators: "[Headers][cplayback:42][splayback:42][i:~q]", Listeners: []string{"127.0.0.1:8080"}}
					line := m.footer()[0]
					for _, want := range []string{"⇧", "M", "[Headers]", "42", "127.0.0.1:8080"} {
						if !strings.Contains(line, want) {
							t.Fatalf("status missing %q: %q", want, line)
						}
					}
					m.snapshot.Total, m.snapshot.FocusIndex = 10000, 0
					m.snapshot.Status = contract.Status{Indicators: "[Headers]"}
					want := "⇩  [1/10000][Headers]" + strings.Repeat(" ", 59)
					if diff := cmp.Diff(want, m.footer()[0]); diff != "" {
						t.Fatal("large flow count must be padded, not truncated (-want +got): " + diff)
					}
				case "test_shorten_message_narrow":
					if ShortenMessage("error", 4) != "…(more in eventlog)" {
						t.Fatal("narrow shortening lost prompt")
					}
				case "test_console_quickhelp_option", "test_console_quickhelp_toggle":
					for _, visible := range []bool{true, false, true} {
						mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
							return b.cfg.Master.Options.Update(ctx, map[string]any{"console_quickhelp_visible": visible})
						}))
						refresh()
						want := 1
						if visible {
							want = 3
						}
						if len(m.footer()) != want {
							t.Fatal("quickhelp visibility mismatch")
						}
					}
				case "test_console_quickhelp_hotkey":
					mustConsole(t, b.cfg.Master.Addons.Add(t.Context(), core.New(b.cfg.Master.Addons)))
					for _, want := range []bool{false, true} {
						_, cmd := m.Update(tea.KeyPressMsg{Code: 'H', Text: "H"})
						if cmd == nil {
							t.Fatal("hotkey did not dispatch")
						}
						m.Update(cmd())
						if b.cfg.Master.Options.Bool("console_quickhelp_visible") != want {
							t.Fatal("hotkey did not toggle")
						}
					}
				case "test_console_quickhelp_prompts_visible_when_disabled":
					mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
						return b.cfg.Master.Options.Update(ctx, map[string]any{"console_quickhelp_visible": false})
					}))
					refresh()
					if len(m.footer()) != 1 {
						t.Fatal("hidden quickhelp visible")
					}
					m.message = "Test message"
					if len(m.footer()) != 3 {
						t.Fatal("hidden quickhelp suppressed message")
					}
					m.message = ""
					for _, prompt := range []string{"text", "command", "onekey"} {
						m.state.Prompt = prompt
						if len(m.footer()) != 3 {
							t.Fatalf("suppressed %s prompt", prompt)
						}
						if diff := cmp.Diff(tea.NewCursor(4, 22), m.View().Cursor); diff != "" {
							t.Fatalf("%s input cursor (-want +got): %s", prompt, diff)
						}
					}
					m.factories = map[string]WidgetFactory{"commander": func(host contract.Host) contract.Widget { return commander.New(t.Context(), host) }}
					for _, width := range []int{80, 200} {
						m.width = width
						m.state.Prompt, m.state.Text = "command", "console.view.flow "
						m.refreshWidgets()
						footer := m.footer()
						if len(footer) != 3 || footer[2] != strings.Repeat(" ", width) {
							t.Fatalf("command footer at width %d: %q", width, footer)
						}
						view := m.View()
						if diff := cmp.Diff(tea.NewCursor(2, 22), view.Cursor); diff != "" {
							t.Fatal("commander cursor (-want +got): " + diff)
						}
						frame := strings.Split(ansi.Strip(view.Content), "\n")
						if diff := cmp.Diff(footer[0], frame[21]); diff != "" {
							t.Fatal("command moved status row (-want +got): " + diff)
						}
						if !strings.HasPrefix(frame[22], ":") || strings.TrimSpace(frame[23]) != "" {
							t.Fatalf("command and empty rows not in final two positions: %q", frame[22:])
						}
					}
					m.state.Prompt = ""
					if len(m.footer()) != 1 {
						t.Fatal("prompt did not restore hidden bar")
					}
				}
			})
		}
	})
}
