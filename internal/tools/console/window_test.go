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
	teatest "github.com/charmbracelet/x/exp/teatest/v2"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
	"github.com/zchee/mitmproxy-go/options"
)

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
						title := state.Panes[i].Stack[0].Name
						if !strings.Contains(frame, m.palette.Style(tag).Render(style.Fit(title, rect.Width))) {
							t.Fatalf("%s pane %d missing %s header styling: %q", name, i, tag, strings.Split(frame, "\n")[rect.Y-1])
						}
					}
				case "overlay_stack":
					var err error
					state, err = reduce(state, contract.Action{Kind: "push", Window: contract.Window{Name: "options", Context: "options"}})
					mustConsole(t, err)
					state, err = reduce(state, contract.Action{Kind: "overlay", Window: contract.Window{Name: "chooser", Context: "chooser"}})
					mustConsole(t, err)
					if _, ok := state.Current("options", true); ok {
						t.Fatal("overlay did not hide current widget")
					}
					if _, ok := state.Current("options", false); !ok {
						t.Fatal("overlay hid current window")
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
					tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(80, 24))
					tm.Send(tea.WindowSizeMsg{Width: 200, Height: 50})
					mustConsole(t, tm.Quit())
					final := tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(*Model)
					if final.width != 200 || final.height != 50 {
						t.Fatal("resize lost")
					}
					if len(strings.Split(final.View().Content, "\n")) != 50 {
						t.Fatal("resized frame height wrong")
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
					snapshot := contract.Snapshot{Bindings: keymap.NewDefault(nil).Snapshot()}
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
					if tt.nested && !strings.Contains(rows[1], "Back") {
						t.Fatal("nested help lost Back")
					}
				})
			}
		})
		t.Run("test_make_rows", func(t *testing.T) {
			items := []helpItem{{short: "bound", help: "Select"}, {short: "unbound", help: "missing"}, {short: "basic", key: "↓"}}
			row := helpRow("test", items, keymap.NewDefault(nil).Snapshot(), 9, 80)
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
