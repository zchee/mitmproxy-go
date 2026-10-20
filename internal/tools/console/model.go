// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"slices"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

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
	// Clipboard access stays behind the application's explicit clipboard support.
	m.input.KeyMap.Paste.Unbind()
	if bridge != nil {
		m.installer = NewInstaller(bridge.Control)
	}
	return m
}

// NewProgram binds one terminal program to the bridge's cancelable lifetime.
func NewProgram(model *Model, options ...tea.ProgramOption) (*tea.Program, error) {
	if model.bridge == nil {
		return nil, errors.New("console program requires a live bridge")
	}
	if model.program != nil {
		return nil, errors.New("console model already has a program")
	}
	options = append(options, tea.WithContext(model.bridge.Context()))
	model.program = tea.NewProgram(model, options...)
	return model.program, nil
}

// Init starts the owned snapshot and external-effect consumers outside dispatch.
func (m *Model) Init() tea.Cmd {
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

func (m *Model) refreshWidgets() {
	m.snapshot.Control = m.state.Clone()
	for i, r := range Layout(m.state, m.width, m.height, len(m.footer())) {
		if w := m.widget(i); w != nil {
			w.Resize(r.Width, r.Height)
			w.SetSnapshot(m.snapshot.Clone())
		}
	}
}

func (m *Model) install(effects contract.EffectsMsg) []tea.Cmd {
	if m.installer == nil {
		return nil
	}
	var commands []tea.Cmd
	for _, effect := range m.installer.Install(effects) {
		m.state = effect.State.Clone()
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
		if w := m.widget(m.state.Pane); w != nil {
			cmd, _ := w.Update(effect)
			if cmd != nil {
				commands = append(commands, cmd)
			}
		}
	}
	return commands
}

func (m *Model) invoke(line string, recipe *contract.Recipe, choice string) tea.Cmd {
	return func() tea.Msg {
		ctx, finish := BeginInvocation(m.bridge.Context())
		var result contract.Result
		var err error
		if recipe != nil {
			result, err = m.bridge.Resolve(ctx, *recipe, choice)
		} else {
			result, err = m.bridge.Execute(ctx, line)
		}
		return resultMsg{result: result, effects: finish(), err: err}
	}
}

func (m *Model) transition(action contract.Action) tea.Cmd {
	if m.bridge == nil {
		return nil
	}
	return func() tea.Msg {
		ctx, finish := BeginInvocation(m.bridge.Context())
		err := m.bridge.Dispatch(ctx, action)
		return resultMsg{effects: finish(), err: err}
	}
}

// Update installs owned results and schedules live work, never calling Do or Send.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(0, msg.Width), max(0, msg.Height)
		m.input.SetWidth(max(0, m.width-2))
		m.refreshWidgets()
		if m.bridge != nil {
			m.bridge.RequestViewport(contract.Viewport{Width: m.width, Height: max(0, m.height-len(m.footer()))})
		}
	case contract.SnapshotMsg:
		if msg.Err != nil {
			m.message = msg.Err.Error()
		}
		if m.bridge == nil || m.bridge.Accept(msg.Snapshot) {
			m.snapshot = msg.Snapshot
			m.refreshWidgets()
		}
	case contract.EffectsMsg:
		return m, tea.Batch(m.install(msg)...)
	case resultMsg:
		if msg.err != nil {
			m.message = msg.err.Error()
		} else if msg.result.Text != "" {
			m.message = msg.result.Text
		}
		return m, tea.Batch(m.install(msg.effects)...)
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
	case tea.KeyPressMsg:
		if m.state.Prompt != "" {
			switch msg.String() {
			case "esc":
				return m, m.transition(contract.Action{Kind: "prompt_done"})
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
	}
	return m, nil
}

func (m *Model) footer() []string {
	footer := []string{StatusLine(m.snapshot, m.width)}
	if m.state.Prompt != "" {
		return append(footer, style.Fit(style.Escape(m.state.Prompt)+": "+m.input.View(), m.width), strings.Repeat(" ", m.width))
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
	v := tea.NewView(Compose(m.state, panes, m.width, m.height, m.footer()))
	v.AltScreen = true
	if m.state.Mouse {
		v.MouseMode = tea.MouseModeCellMotion
	}
	return v
}
