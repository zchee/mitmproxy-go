// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package commander

import (
	"context"
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// Model owns a command prompt, its completion hints and detached command output.
// Its context must be the frontend lifetime, never a dispatch-frame context.
type Model struct {
	ctx                        context.Context
	host                       contract.Host
	buffer                     Buffer
	state                      contract.State
	initialPrompt, initialText string
	initialCursor              int
	active, busy, filterActive bool
	filter                     string
	epoch                      uint64
	pending                    []tea.Msg
	hints                      contract.Completion
	result                     contract.Result
	err                        error
	width, height              int
	choice                     int
	palette                    style.Palette
}

type response struct {
	owner       *Model
	epoch       uint64
	kind        string
	text        string
	completion  contract.Completion
	forward     bool
	resetFilter bool
	result      contract.Result
	err         error
}

var _ contract.Widget = (*Model)(nil)

// New returns a prompt widget using the existing registry through host.
func New(ctx context.Context, host contract.Host) *Model {
	palette, _ := style.NewPalette("solarized_dark", true)
	return &Model{ctx: ctx, host: host, width: 80, height: 1, palette: palette}
}

// SetSnapshot installs an owned prompt request without overwriting local typing.
func (m *Model) SetSnapshot(snapshot contract.Snapshot) {
	s := snapshot.Control.Clone()
	if s.Prompt != m.initialPrompt || s.Text != m.initialText || s.Cursor != m.initialCursor {
		m.epoch++
		m.initialPrompt, m.initialText, m.initialCursor = s.Prompt, s.Text, s.Cursor
		m.buffer = NewBuffer(s.Text)
		m.buffer.SetCursor(s.Cursor)
		m.active = s.Prompt != ""
		m.pending = nil
		m.hints = contract.Completion{}
		m.filterActive, m.filter, m.choice = false, "", 0
		m.err = nil
	}
	m.state = s
	name, transparent := "solarized_dark", true
	for _, option := range snapshot.Options {
		switch option.Name() {
		case "console_palette":
			name, _ = option.Current().(string)
		case "console_palette_transparent":
			transparent, _ = option.Current().(bool)
		}
	}
	if palette, err := style.NewPalette(name, transparent); err == nil {
		m.palette = palette
	} else {
		m.err = err
	}
}

// Resize sets the available prompt dimensions.
func (m *Model) Resize(width, height int) { m.width, m.height = max(0, width), max(0, height) }

// Active reports whether a command or choice prompt owns keyboard input.
func (m *Model) Active() bool { return m.active }

// Text returns the current command line.
func (m *Model) Text() string { return m.buffer.Text() }

// Cursor returns the command's rune-indexed cursor position.
func (m *Model) Cursor() int { return m.buffer.Cursor() }

// Error returns the last registry or input error for the status renderer.
func (m *Model) Error() error { return m.err }

// Result returns the last detached command result; callers must not mutate it.
func (m *Model) Result() contract.Result { return m.result }

// Update handles local editing and returns all live work as a command.
// Input arriving during a registry request is replayed in order after its reply.
func (m *Model) Update(msg tea.Msg) (tea.Cmd, bool) {
	if r, ok := msg.(response); ok {
		if r.owner != m {
			return nil, false
		}
		m.busy = false
		if r.epoch == m.epoch {
			m.err = r.err
			if r.err == nil {
				switch r.kind {
				case "hints":
					m.hints = r.completion
				case "complete":
					m.buffer.Complete(r.completion, r.forward)
					return m.complete(false, true), true
				case "history":
					m.buffer.SetText(r.text)
					if r.resetFilter {
						m.filterActive, m.filter = false, ""
					}
				case "execute":
					m.result = r.result
				}
			}
		}
		if len(m.pending) > 0 {
			next := m.pending[0]
			m.pending = m.pending[1:]
			cmd, _ := m.Update(next)
			return cmd, true
		}
		return nil, true
	}
	if !m.active {
		return nil, false
	}
	switch msg.(type) {
	case tea.KeyPressMsg, tea.PasteMsg:
		if m.busy {
			m.pending = append(m.pending, msg)
			return nil, true
		}
	default:
		return nil, false
	}
	if key, ok := msg.(tea.KeyPressMsg); ok {
		if key.String() == "esc" {
			return m.finish(false, ""), true
		}
		if len(m.state.Choices) > 0 {
			return m.updateChoice(key), true
		}
		switch key.String() {
		case "enter":
			return m.finish(true, ""), true
		case "left", "ctrl+b":
			m.buffer.Left()
		case "right", "ctrl+f":
			m.buffer.Right()
		case "home", "ctrl+a":
			m.buffer.SetCursor(0)
		case "end", "ctrl+e":
			m.buffer.SetCursor(len([]rune(m.buffer.Text())))
		case "alt+b":
			m.buffer.WordLeft()
		case "alt+f":
			m.buffer.WordRight()
		case "ctrl+w":
			m.buffer.DeleteWord()
		case "backspace":
			m.buffer.Backspace()
			if m.buffer.Text() == "" {
				m.filterActive, m.filter = false, ""
				return m.historyReset(), true
			}
		case "delete":
			m.buffer.Delete()
		case "up", "ctrl+p":
			return m.history(true), true
		case "down", "ctrl+n":
			return m.history(false), true
		case "tab", "shift+tab":
			forward := key.String() == "tab"
			if m.buffer.Completing() {
				m.buffer.Complete(contract.Completion{}, forward)
				return nil, true
			}
			return m.complete(true, forward), true
		default:
			if key.Text != "" {
				m.buffer.Insert(key.Text)
			}
		}
	} else if paste, ok := msg.(tea.PasteMsg); ok {
		m.buffer.Insert(paste.Content)
	}
	return m.complete(false, true), true
}

func (m *Model) request(kind string, work func(*response)) tea.Cmd {
	m.busy = true
	r := response{owner: m, epoch: m.epoch, kind: kind}
	return func() tea.Msg { work(&r); return r }
}

func (m *Model) complete(cycle, forward bool) tea.Cmd {
	prefix, line := m.buffer.BeforeCursor(), m.buffer.Text()
	kind := "hints"
	if cycle {
		kind = "complete"
	}
	return m.request(kind, func(r *response) { r.completion, r.err = m.host.Complete(m.ctx, prefix, line); r.forward = forward })
}

func (m *Model) historyReset() tea.Cmd {
	return m.request("hints", func(r *response) {
		_, r.err = m.host.Call(m.ctx, "commands.history.filter", "")
	})
}

func (m *Model) history(previous bool) tea.Cmd {
	startFilter := previous && !m.filterActive
	prefix, prior := m.buffer.Text(), m.buffer.Text()
	if startFilter {
		m.filterActive, m.filter = true, prefix
	}
	filter := m.filter
	return m.request("history", func(r *response) {
		r.err = m.host.Do(m.ctx, func(ctx context.Context) error {
			if startFilter {
				if _, err := m.host.Call(ctx, "commands.history.filter", prefix); err != nil {
					return err
				}
			}
			name := "commands.history.next"
			if previous {
				name = "commands.history.prev"
			}
			value, err := m.host.Call(ctx, name)
			if err != nil {
				return err
			}
			text, ok := value.(string)
			if !ok {
				return fmt.Errorf("%s returned %T, not a string", name, value)
			}
			if !previous && text == "" {
				if prior == filter {
					text = prior
				} else {
					if _, err := m.host.Call(ctx, "commands.history.filter", ""); err != nil {
						return err
					}
					r.resetFilter = true
				}
			}
			r.text = text
			return nil
		})
	})
}

func (m *Model) updateChoice(key tea.KeyPressMsg) tea.Cmd {
	choices := m.state.Choices
	switch key.String() {
	case "q":
		return m.finish(false, "")
	case "up", "k":
		m.choice = max(0, m.choice-1)
	case "down", "j":
		m.choice = min(len(choices)-1, m.choice+1)
	case "home":
		m.choice = 0
	case "end":
		m.choice = len(choices) - 1
	case "enter":
		return m.finish(m.state.Prompt != "confirm" || choices[m.choice].Value != "n", choices[m.choice].Value)
	default:
		if m.state.Prompt == "confirm" && (key.Text == "y" || key.Text == "n") {
			return m.finish(key.Text == "y", key.Text)
		}
		const shortcuts = "123456789abcdefghijklmnoprstuvwxyz"
		if len(key.Text) == 1 {
			if i := strings.Index(shortcuts, key.Text); i >= 0 && i < len(choices) {
				return m.finish(m.state.Prompt != "confirm" || choices[i].Value != "n", choices[i].Value)
			}
		}
	}
	return nil
}

func (m *Model) finish(execute bool, choice string) tea.Cmd {
	line, recipe := m.buffer.Text(), m.state.Recipe
	recipe.Arguments = slices.Clone(recipe.Arguments)
	recipe.ChoiceIndices = slices.Clone(recipe.ChoiceIndices)
	m.active = false
	return m.request("execute", func(r *response) {
		r.err = m.host.Do(m.ctx, func(ctx context.Context) error {
			if err := m.host.Dispatch(ctx, contract.Action{Kind: "prompt_done"}); err != nil {
				return err
			}
			if !execute {
				return nil
			}
			var err error
			if recipe.Command != "" {
				r.result, err = m.host.Resolve(ctx, recipe, choice)
			} else if strings.TrimSpace(line) != "" {
				if _, err = m.host.Call(ctx, "commands.history.add", line); err != nil {
					return err
				}
				r.result, err = m.host.Execute(ctx, line)
			}
			return err
		})
	})
}

// View renders escaped prompt text and hints, never live registry state.
func (m *Model) View() string {
	if m.width == 0 || m.height == 0 {
		return ""
	}
	if m.err != nil {
		return style.Truncate(style.Escape(m.err.Error()), m.width)
	}
	if len(m.state.Choices) > 0 && m.active {
		title := m.state.Prompt
		if title == "choice" || title == "confirm" {
			title = m.state.Text
		}
		lines := []string{style.Escape(title)}
		for i, choice := range m.state.Choices {
			prefix := "  "
			if i == m.choice {
				prefix = "> "
			}
			lines = append(lines, style.Truncate(prefix+style.Escape(choice.Label), m.width))
		}
		return strings.Join(lines[:min(len(lines), m.height)], "\n")
	}
	if m.active {
		text := ": "
		var parsed strings.Builder
		for _, token := range m.hints.Tokens {
			parsed.WriteString(token.Value)
		}
		if parsed.String() == m.buffer.Text() {
			for _, token := range m.hints.Tokens {
				tag := "text"
				if !token.Valid {
					tag = "commander_invalid"
				} else if token.Type == "Cmd" {
					tag = "commander_command"
				}
				text += m.palette.Render(tag, token.Value)
			}
		} else {
			text += m.palette.Render("text", m.buffer.Text())
		}
		if len(m.hints.Tokens) > 0 && len(m.hints.Remaining) > 0 {
			if !strings.HasSuffix(m.buffer.Text(), " ") {
				text += " "
			}
			text += m.palette.Render("commander_hint", strings.Join(m.hints.Remaining, " ")+" ")
		}
		return style.Truncate(text, m.width)
	}
	if len(m.result.Flows) > 0 {
		return fmt.Sprintf("Command returned %d flows", len(m.result.Flows))
	}
	lines := append([]string{m.result.Text}, m.result.Lines...)
	for _, row := range m.result.Table {
		lines = append(lines, strings.Join(row, "  "))
	}
	if len(m.result.Bytes) > 0 {
		lines = append(lines, string(m.result.Bytes))
	}
	for i := range lines {
		lines[i] = style.Truncate(style.Escape(lines[i]), m.width)
	}
	return strings.Join(lines[:min(len(lines), m.height)], "\n")
}
