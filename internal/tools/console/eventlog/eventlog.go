// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package eventlog presents the bounded event store without retaining another history.
package eventlog

import (
	"context"
	"slices"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

type visibleRow struct {
	id                   uint64
	index, first, height int
}

// Model owns only the current viewport and stable selection, not an event history.
type Model struct {
	ctx                                context.Context
	host                               contract.Host
	viewport                           viewport.Model
	rows                               []visibleRow
	selected                           uint64
	index, total, offset, controlIndex int
	lastID                             uint64
	mouse                              bool
}

// New constructs an event-log widget using the frontend's lifetime context.
func New(ctx context.Context, host contract.Host) *Model {
	return &Model{ctx: ctx, host: host, viewport: viewport.New(), controlIndex: -1}
}

// Resize sets the physical viewport dimensions; the next snapshot reprojects rows.
func (m *Model) Resize(width, height int) {
	m.viewport.SetWidth(max(0, width))
	m.viewport.SetHeight(max(0, height))
}

// SetSnapshot filters owned records and preserves selection through ring eviction.
func (m *Model) SetSnapshot(snapshot contract.Snapshot) {
	verbosity, paletteName, transparent, follow := "info", "solarized_dark", true, false
	for _, option := range snapshot.Options {
		switch option.Name() {
		case "console_eventlog_verbosity":
			verbosity, _ = option.Current().(string)
		case "console_palette":
			paletteName, _ = option.Current().(string)
		case "console_palette_transparent":
			transparent, _ = option.Current().(bool)
		case "console_focus_follow":
			follow, _ = option.Current().(bool)
		}
	}
	palette, err := style.NewPalette(paletteName, transparent)
	if err != nil {
		palette, _ = style.NewPalette("solarized_dark", transparent)
	}
	m.mouse = snapshot.Control.Mouse
	records := make([]eventstore.Record, 0, len(snapshot.Events))
	for _, record := range snapshot.Events {
		if levelTier(record.Entry.LevelName()) <= levelTier(verbosity) {
			records = append(records, record)
		}
	}
	m.total = len(records)
	m.rows = m.rows[:0]
	if m.total == 0 {
		m.selected, m.index, m.offset = 0, 0, 0
		m.viewport.SetContent("")
		return
	}
	latest := records[len(records)-1].ID
	window, _ := snapshot.Control.Current("eventlog", false)
	if window.Index != m.controlIndex {
		m.index = min(max(window.Index, 0), m.total-1)
	} else if index := slices.IndexFunc(records, func(record eventstore.Record) bool { return record.ID == m.selected }); index >= 0 {
		m.index = index
	} else {
		m.index = min(m.index, m.total-1)
	}
	m.controlIndex = window.Index
	if follow && latest > m.lastID {
		m.index = m.total - 1
	}
	m.lastID = latest
	m.selected = records[m.index].ID
	if m.viewport.Width() == 0 || m.viewport.Height() == 0 {
		m.viewport.SetContent("")
		return
	}
	m.offset = min(max(m.offset, 0), m.index)
	if m.index >= m.offset+m.viewport.Height() || follow && m.index == m.total-1 {
		m.offset = max(0, m.index-m.viewport.Height()+1)
	}
	// A record can wrap to several physical rows. Advancing the origin until the
	// selection fits costs at most two viewport-sized groups of formatted records.
	lines := m.project(records, palette)
	if !slices.ContainsFunc(m.rows, func(row visibleRow) bool { return row.id == m.selected }) {
		m.offset = m.index
		lines = m.project(records, palette)
	}
	m.viewport.SetContent(strings.Join(lines, "\n"))
	m.viewport.SetYOffset(0)
}

func (m *Model) project(records []eventstore.Record, palette style.Palette) []string {
	m.rows = m.rows[:0]
	lines := make([]string, 0, m.viewport.Height())
	for i := m.offset; i < len(records) && len(lines) < m.viewport.Height(); i++ {
		record := records[i]
		level := record.Entry.LevelName()
		text := style.Escape(level + ": " + record.Entry.Msg)
		wrapped := strings.Split(ansi.Wrap(text, m.viewport.Width(), ""), "\n")
		remaining := m.viewport.Height() - len(lines)
		wrapped = wrapped[:min(len(wrapped), remaining)]
		m.rows = append(m.rows, visibleRow{id: record.ID, index: i, first: len(lines), height: len(wrapped)})
		for _, line := range wrapped {
			if level == "error" || level == "warn" || level == "alert" {
				line = palette.Style(level).Render(line)
			}
			lines = append(lines, style.Fit(line, m.viewport.Width()))
		}
	}
	return lines
}

func levelTier(level string) int {
	switch level {
	case "error":
		return 0
	case "warn":
		return 1
	case "info", "alert":
		return 2
	default:
		return 3
	}
}

// Update handles local navigation and leaves other keys to the console keymap.
// Mouse coordinates are relative to this widget's body, after pane/header offsets.
func (m *Model) Update(message tea.Msg) (tea.Cmd, bool) {
	index, command := m.index, ""
	switch message := message.(type) {
	case tea.KeyPressMsg:
		switch message.String() {
		case "up":
			command = "console.nav.up"
		case "down":
			command = "console.nav.down"
		case "pgup":
			command = "console.nav.pageup"
		case "pgdown":
			command = "console.nav.pagedown"
		case "home":
			command = "console.nav.start"
		case "end":
			command = "console.nav.end"
		default:
			return nil, false
		}
	case tea.MouseClickMsg:
		if !m.mouse || message.Button != tea.MouseLeft || message.X < 0 || message.X >= m.viewport.Width() {
			return nil, false
		}
		found := false
		for _, row := range m.rows {
			if message.Y >= row.first && message.Y < row.first+row.height {
				index, found = row.index, true
				break
			}
		}
		if !found {
			return nil, false
		}
	case tea.MouseWheelMsg:
		if !m.mouse {
			return nil, false
		}
		switch message.Button {
		case tea.MouseWheelUp:
			command = "console.nav.up"
		case tea.MouseWheelDown:
			command = "console.nav.down"
		default:
			return nil, false
		}
	default:
		return nil, false
	}
	if m.total == 0 {
		return nil, true
	}
	index = min(max(index, 0), m.total-1)
	return func() tea.Msg {
		if command != "" {
			_, err := m.host.Execute(m.ctx, command)
			return err
		}
		if err := m.host.Dispatch(m.ctx, contract.Action{Kind: "selection", Value: "eventlog", Index: index}); err != nil {
			return err
		}
		return nil
	}, true
}

// View renders only the already-projected viewport.
func (m *Model) View() string { return m.viewport.View() }

var _ contract.Widget = (*Model)(nil)
