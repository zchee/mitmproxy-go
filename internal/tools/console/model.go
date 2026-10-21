// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// WidgetFactory creates an independent widget for each pane.
type WidgetFactory func(contract.Host) contract.Widget

// Model is the presentation-only Bubble Tea model. Live access occurs in Cmd.
type Model struct {
	bridge        *Bridge
	installer     *Installer
	program       *tea.Program
	factories     map[string]WidgetFactory
	widgets       [2]map[string]contract.Widget
	width, height int
	snapshot      contract.Snapshot
	state         contract.State
	message       string
	input         textinput.Model
	prompt        contract.Widget
	palette       style.Palette
	lastEvent     uint64
	processes     sync.Map
	ready         func()
}

type resultMsg struct {
	result  contract.Result
	effects contract.EffectsMsg
	err     error
}

// NewModel creates a presentation model with no terminal or background work.
// Base widgets may be omitted while assembling; views are installed explicitly.
func NewModel(bridge *Bridge, factories map[string]WidgetFactory) *Model {
	m := &Model{bridge: bridge, factories: factories, width: 80, height: 24, state: contract.NewState(), input: textinput.New()}
	m.widgets = [2]map[string]contract.Widget{{}, {}}
	m.palette, _ = style.NewPalette("solarized_dark", true)
	// Clipboard access stays behind the application's explicit clipboard support.
	m.input.KeyMap.Paste.Unbind()
	if bridge != nil {
		m.installer = NewInstaller(bridge.Control)
	}
	return m
}

// NewProgram binds one terminal program, defaulting to the bridge's lifetime.
// Cancelling that default context uses Bubble Tea's kill teardown without joining
// its input read loop. Use Master.NewProgram for orderly shutdown; an owner that
// joins the program before closing the bridge may override its context.
func NewProgram(model *Model, options ...tea.ProgramOption) (*tea.Program, error) {
	if model.bridge == nil {
		return nil, errors.New("console program requires a live bridge")
	}
	if model.program != nil {
		return nil, errors.New("console model already has a program")
	}
	options = append([]tea.ProgramOption{tea.WithContext(model.bridge.Context())}, options...)
	model.program = tea.NewProgram(model, options...)
	return model.program, nil
}

// Init starts the owned snapshot and external-effect consumers outside dispatch.
func (m *Model) Init() tea.Cmd {
	if m.ready != nil {
		m.ready()
	}
	if m.program == nil {
		return nil
	}
	return tea.Batch(m.bridge.Drain(m.program), m.bridge.DeliverEffects(m.program))
}

func (m *Model) widget(pane int) contract.Widget {
	p := m.state.Panes[pane]
	if len(p.Stack) == 0 {
		return nil
	}
	window := p.Stack[len(p.Stack)-1]
	if p.Overlay != nil {
		window = *p.Overlay
	}
	if w := m.widgets[pane][window.Name]; w != nil {
		return w
	}
	factory := m.factories[window.Name]
	if factory == nil && window.Context == "help" {
		factory = func(contract.Host) contract.Widget { return NewHelpWidget("") }
	}
	if factory == nil {
		return nil
	}
	w := factory(m.bridge)
	m.widgets[pane][window.Name] = w
	return w
}

func (m *Model) promptWidget() contract.Widget {
	if m.prompt == nil && m.factories["commander"] != nil {
		m.prompt = m.factories["commander"](m.bridge)
	}
	return m.prompt
}

func (m *Model) refreshWidgets() {
	m.snapshot.Control = m.state.Clone()
	if w := m.promptWidget(); w != nil {
		w.Resize(m.width, max(1, m.height/2))
		w.SetSnapshot(m.snapshot.Clone())
	}
	for i, r := range Layout(m.state, m.width, m.height, len(m.footer())) {
		if w := m.widget(i); w != nil {
			w.Resize(r.Width, r.Height)
			w.SetSnapshot(m.snapshot.Clone())
		}
	}
}

func (m *Model) applySnapshot(snapshot contract.Snapshot) {
	for i := range m.state.Panes {
		for j := range m.state.Panes[i].Stack {
			window := &m.state.Panes[i].Stack[j]
			if window.Context == "flowview" && j < len(snapshot.Control.Panes[i].Stack) {
				projected := snapshot.Control.Panes[i].Stack[j]
				if projected.Context == "flowview" && len(projected.Tabs) > window.Index && window.Index >= 0 {
					window.FlowID = projected.FlowID
					window.Tabs = slices.Clone(projected.Tabs)
					window.Mode = projected.Tabs[window.Index].Mode
				}
			}
		}
	}
	name, transparent := "solarized_dark", true
	for _, option := range snapshot.Options {
		switch option.Name() {
		case "console_palette":
			name, _ = option.Current().(string)
		case "console_palette_transparent":
			transparent, _ = option.Current().(bool)
		}
	}
	if name != m.palette.Name || transparent != m.palette.Transparent {
		palette, err := style.NewPalette(name, transparent)
		if err != nil {
			m.message = err.Error()
		} else {
			m.palette = palette
		}
	}
	for _, record := range snapshot.Events {
		if record.ID <= m.lastEvent {
			continue
		}
		m.lastEvent = record.ID
		switch record.Entry.LevelName() {
		case "warn", "error", "alert":
			m.message = record.Entry.Msg
		}
	}
	m.snapshot = snapshot
	m.refreshWidgets()
}

func (m *Model) showResult(result contract.Result) tea.Cmd {
	if result.Kind == "flow" {
		m.message = "Command returned 1 flow"
		return nil
	}
	if result.Kind == "flows" || result.Flows != nil {
		m.message = fmt.Sprintf("Command returned %d flows", len(result.Flows))
		return nil
	}
	if result.Kind == "" && result.Text == "" && result.Bytes == nil && result.Lines == nil && result.Table == nil {
		return nil
	}
	lines := []string{result.Text}
	if result.Bytes != nil {
		lines = []string{string(result.Bytes)}
	}
	if result.Lines != nil {
		lines = result.Lines
	}
	if result.Table != nil {
		lines = make([]string, len(result.Table))
		for i, row := range result.Table {
			lines[i] = strings.Join(row, "  ")
		}
	}
	return m.transition(contract.Action{Kind: "overlay", Window: contract.Window{Name: "dataviewer", Context: "dataviewer"}, Text: strings.Join(lines, "\n")})
}

func (m *Model) install(effects contract.EffectsMsg) []tea.Cmd {
	if m.installer == nil {
		return nil
	}
	var commands []tea.Cmd
	for _, effect := range m.installer.Install(effects) {
		m.state = effect.State.Clone()
		if effect.Action.Kind == "push" && effect.Action.Grid != nil && m.factories[effect.Action.Window.Name] == nil {
			if err := m.installGrid(effect.Action); err != nil {
				m.message = err.Error()
			}
		}
		if effect.Action.Kind == "external" {
			commands = append(commands, m.externalCommand(effect.Action))
		}
		if effect.Action.Kind == "pop" && m.state.QuitPrompt {
			commands = append(commands, m.confirmExit())
		}
		if effect.Action.Kind == "overlay" && effect.Action.Window.Name == "dataviewer" {
			m.widgets[m.state.Pane]["dataviewer"] = newResultWidget(m.bridge, effect.Action.Text)
		}
		if effect.Action.Kind == "prompt" {
			m.input.SetValue(m.state.Text)
			m.input.SetCursor(m.state.Cursor)
			m.input.Focus()
		}
		if effect.Action.Kind == "keymap_load" {
			path := effect.Action.Value
			commands = append(commands, func() tea.Msg {
				bindings, present, err := keymap.ReadPath(path)
				if err == nil && present {
					err = m.bridge.Do(m.bridge.Context(), func(context.Context) error {
						if m.bridge.Keys == nil {
							return errors.New("keymap is not installed")
						}
						return m.bridge.Keys.Install(bindings)
					})
				}
				return resultMsg{err: err}
			})
		}
		m.refreshWidgets()
		targetPane := m.state.Pane
		if effect.Action.Kind == "grid" {
			for _, candidate := range [2]int{m.state.Pane, 1 - m.state.Pane} {
				pane := m.state.Panes[candidate]
				window := pane.Stack[len(pane.Stack)-1]
				if pane.Overlay != nil {
					window = *pane.Overlay
				}
				if window.Context == "grideditor" {
					targetPane = candidate
					break
				}
			}
		}
		if w := m.widget(targetPane); w != nil {
			if effect.Action.Kind == "grid" && effect.Action.Value == "commit" {
				if committer, ok := w.(interface{ Commit() tea.Cmd }); ok {
					window, _ := m.state.Current("", true)
					commands = append(commands, m.commitAndPop(committer.Commit(), window))
					continue
				}
			}
			cmd, _ := w.Update(effect.Action.Clone())
			if cmd != nil {
				commands = append(commands, cmd)
			}
		}
	}
	return commands
}

func (m *Model) invoke(line string, recipe *contract.Recipe, choice string) tea.Cmd {
	return m.bridge.command(func() tea.Msg {
		ctx, finish := BeginInvocation(m.bridge.Context())
		var result contract.Result
		var err error
		if recipe != nil {
			result, err = m.bridge.Resolve(ctx, *recipe, choice)
		} else {
			result, err = m.bridge.Execute(ctx, line)
		}
		return resultMsg{result: result, effects: finish(), err: err}
	})
}

func (m *Model) transition(action contract.Action) tea.Cmd {
	if m.bridge == nil {
		return nil
	}
	return m.bridge.command(func() tea.Msg {
		ctx, finish := BeginInvocation(m.bridge.Context())
		err := m.bridge.Dispatch(ctx, action)
		return resultMsg{effects: finish(), err: err}
	})
}

// Update installs owned results and schedules live work, never calling Do or Send.
func (m *Model) Update(msg tea.Msg) (model tea.Model, cmd tea.Cmd) {
	defer func() {
		if m.bridge != nil {
			cmd = m.bridge.command(cmd)
		}
	}()
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(0, msg.Width), max(0, msg.Height)
		m.input.SetWidth(max(0, m.width-2))
		m.refreshWidgets()
		if m.bridge != nil {
			m.bridge.RequestViewport(contract.Viewport{Width: m.width, Height: max(0, m.height-len(m.footer()))})
		}
	case processReadyMsg:
		return m, msg.command
	case processFinishedMsg:
		return m, m.finishProcess(msg)
	case contract.ErrorMsg:
		if msg.Err != nil {
			m.message = msg.Err.Error()
		}
	case contract.SnapshotMsg:
		if msg.Err != nil {
			m.message = msg.Err.Error()
		}
		if m.bridge == nil || m.bridge.Accept(msg.Snapshot) {
			m.applySnapshot(msg.Snapshot)
		}
	case contract.EffectsMsg:
		return m, tea.Batch(m.install(msg)...)
	case contract.Result:
		return m, m.showResult(msg)
	case resultMsg:
		commands := m.install(msg.effects)
		if msg.err != nil {
			m.message = msg.err.Error()
		} else {
			commands = append(commands, m.showResult(msg.result))
		}
		return m, tea.Batch(commands...)
	case tea.MouseClickMsg:
		if !m.state.Mouse {
			return m, nil
		}
		rects := Layout(m.state, m.width, m.height, len(m.footer()))
		pane, col, row, ok := Hit(rects, msg.X, msg.Y, [2]int{})
		if !ok {
			return m, nil
		}
		if pane != m.state.Pane {
			return m, m.transition(contract.Action{Kind: "pane"})
		}
		if w := m.widget(pane); w != nil {
			msg.X, msg.Y = col, row
			cmd, _ := w.Update(msg)
			return m, cmd
		}
	case tea.PasteMsg:
		if w := m.promptWidget(); w != nil && m.state.Prompt != "" {
			cmd, _ := w.Update(msg)
			return m, cmd
		}
	case tea.KeyPressMsg:
		if m.state.Prompt != "" {
			if w := m.promptWidget(); w != nil {
				cmd, _ := w.Update(msg)
				return m, cmd
			}
			switch msg.String() {
			case "esc":
				return m, m.transition(contract.Action{Kind: "prompt_done"})
			case "n":
				if m.state.Prompt == "confirm" {
					return m, m.transition(contract.Action{Kind: "prompt_done"})
				}
				m.input, _ = m.input.Update(msg)
				return m, nil
			case "enter":
				if m.bridge == nil {
					return m, nil
				}
				text := m.input.Value()
				recipe := m.state.Recipe
				cmd := m.invoke(text, nil, "")
				if recipe.Command != "" {
					cmd = m.invoke("", &recipe, text)
				}
				return m, tea.Sequence(m.transition(contract.Action{Kind: "prompt_done"}), cmd)
			default:
				if len(m.state.Choices) > 0 {
					for _, choice := range m.state.Choices {
						if choice.Value == msg.String() {
							recipe := m.state.Recipe
							return m, tea.Sequence(m.transition(contract.Action{Kind: "prompt_done"}), m.invoke("", &recipe, choice.Value))
						}
					}
					return m, nil
				}
				var cmd tea.Cmd
				m.input, cmd = m.input.Update(msg)
				return m, cmd
			}
		}
		if w := m.widget(m.state.Pane); w != nil {
			cmd, handled := w.Update(msg)
			if handled {
				return m, cmd
			}
		}
		if m.bridge == nil {
			return m, nil
		}
		window, _ := m.state.Current("", true)
		key := strings.ReplaceAll(msg.String(), "+", " ")
		if key == "space" {
			key = " "
		}
		for _, ctx := range []string{window.Context, "global"} {
			for _, binding := range m.snapshot.Bindings {
				if (keymap.Binding{Key: binding.Key}).KeySpec() != key {
					continue
				}
				if slices.Contains(binding.Contexts, ctx) {
					return m, m.invoke(binding.Command, nil, "")
				}
			}
		}
	default:
		// Private widget responses return to their owner even after its view closes.
		if w := m.promptWidget(); w != nil {
			if cmd, consumed := w.Update(msg); consumed {
				return m, cmd
			}
		}
		for _, widgets := range m.widgets {
			for _, w := range widgets {
				if cmd, consumed := w.Update(msg); consumed {
					return m, cmd
				}
			}
		}
	}
	return m, nil
}

func (m *Model) footer() []string {
	footer := []string{StatusLine(m.snapshot, m.width)}
	if m.state.Prompt != "" {
		if w := m.promptWidget(); w != nil {
			return append(footer, strings.Split(w.View(), "\n")...)
		}
		if m.state.Prompt == "choice" || m.state.Prompt == "confirm" {
			return append(footer, style.Fit(style.Escape(m.state.Text), m.width), strings.Repeat(" ", m.width))
		}
		return append(footer, style.Fit(": "+m.input.View(), m.width), strings.Repeat(" ", m.width))
	}
	if m.message != "" {
		return append(footer, style.Fit(ShortenMessage(m.message, m.width), m.width), strings.Repeat(" ", m.width))
	}
	visible := true
	for _, option := range m.snapshot.Options {
		if option.Name() == "console_quickhelp_visible" {
			visible, _ = option.Current().(bool)
		}
	}
	if visible {
		rows := QuickHelp(m.state, m.snapshot, m.width)
		footer = append(footer, rows[:]...)
	}
	return footer
}

// View composes only owned presentation values and declares terminal modes.
func (m *Model) View() tea.View {
	var panes []string
	for i := range Layout(m.state, m.width, m.height, len(m.footer())) {
		text := ""
		if w := m.widget(i); w != nil {
			text = w.View()
		}
		panes = append(panes, text)
	}
	footer := m.footer()
	lines := strings.Split(Compose(m.state, panes, m.width, m.height, footer), "\n")
	if m.state.Headers {
		rawLines := slices.Clone(lines)
		for i, rect := range Layout(m.state, m.width, m.height, len(footer)) {
			row := rect.Y - 1
			if row < 0 || row >= len(lines) {
				continue
			}
			tag := "heading_inactive"
			if i == m.state.Pane {
				tag = "heading"
			}
			if m.state.Layout == "horizontal" {
				line := lines[row]
				end := rect.X + rect.Width
				lines[row] = ansi.Cut(line, 0, rect.X) + m.palette.Style(tag).Render(ansi.Cut(rawLines[row], rect.X, end)) + ansi.Cut(rawLines[row], end, m.width)
			} else {
				lines[row] = m.palette.Style(tag).Render(lines[row])
			}
		}
	}
	if row := len(lines) - len(footer); row >= 0 && row < len(lines) {
		lines[row] = m.palette.Style("heading").Render(lines[row])
	}
	for i := range lines {
		lines[i] = m.palette.Style("text").Render(lines[i])
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	if m.state.Mouse {
		v.MouseMode = tea.MouseModeCellMotion
	}
	return v
}
