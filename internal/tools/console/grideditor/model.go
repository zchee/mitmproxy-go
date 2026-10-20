// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package grideditor

import (
	"bytes"
	"context"
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/tools/console/external"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// Operation is an admitted grid command delivered on the program goroutine.
type Operation struct{ Name, Path string }

// ResultMsg reports completion without hiding an edit or file error.
type ResultMsg struct{ Err error }

type cellMsg struct {
	revision    uint64
	row, column int
	data        []byte
	err         error
}
type processMsg struct {
	revision    uint64
	row, column int
	process     *external.Process
	err         error
}

// Model owns copied working rows and never modifies a live flow directly.
type Model struct {
	ctx                        context.Context
	host                       contract.Host
	session                    *external.EditSession
	columns                    []Column
	rows                       [][]Cell
	row, column, width, height int
	revision                   uint64
	editing                    bool
	input                      string
	err                        error
	option                     string
	child                      *Model
	palette                    style.Palette
}

var _ contract.Widget = (*Model)(nil)

// New creates an editor for a detached flow edit session.
func New(ctx context.Context, host contract.Host, session *external.EditSession) (*Model, error) {
	columns, rows, err := Rows(session)
	if err != nil {
		return nil, err
	}
	palette, _ := style.NewPalette("solarized_dark", true)
	return &Model{ctx: ctx, host: host, session: session, columns: columns, rows: rows, width: 80, height: 22, palette: palette}, nil
}

// NewSequence creates the shared single-column editor for an option sequence.
func NewSequence(ctx context.Context, host contract.Host, request contract.GridRequest) *Model {
	palette, _ := style.NewPalette("solarized_dark", true)
	m := &Model{ctx: ctx, host: host, option: request.Option, columns: []Column{{Name: request.Title}}, width: 80, height: 22, palette: palette}
	for _, row := range request.Rows {
		cells := make([]Cell, len(row))
		for j, value := range row {
			cells[j].Data = []byte(value)
		}
		m.rows = append(m.rows, cells)
	}
	return m
}

// SetSnapshot accepts global display configuration without replacing working edits.
func (m *Model) SetSnapshot(snapshot contract.Snapshot) {
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
	}
}

// Resize changes the editor's cell geometry.
func (m *Model) Resize(width, height int) {
	m.width, m.height = max(1, width), max(1, height)
	if m.child != nil {
		m.child.Resize(width, height)
	}
}

// Values returns independent working cells for save and commit operations.
func (m *Model) Values() [][]Cell { return CloneRows(m.rows) }

// Add inserts a blank row before or after the current row.
func (m *Model) Add(before bool) {
	index := min(m.row+1, len(m.rows))
	if before {
		index = min(m.row, len(m.rows))
	}
	row := make([]Cell, len(m.columns))
	for i := range row {
		row[i].Data = []byte{}
	}
	m.rows = append(m.rows, nil)
	copy(m.rows[index+1:], m.rows[index:])
	m.rows[index] = row
	m.row, m.column = index, 0
	m.revision++
	m.begin()
}

// Delete removes the selected row without leaving an invalid cursor.
func (m *Model) Delete() {
	if len(m.rows) == 0 {
		return
	}
	m.rows = append(m.rows[:m.row], m.rows[m.row+1:]...)
	m.row = min(m.row, max(0, len(m.rows)-1))
	m.column = 0
	m.revision++
}

func (m *Model) current() *Cell {
	if m.row < 0 || m.row >= len(m.rows) || m.column < 0 || m.column >= len(m.rows[m.row]) {
		return nil
	}
	return &m.rows[m.row][m.column]
}

func (m *Model) begin() {
	cell := m.current()
	if cell == nil || m.columns[m.column].ReadOnly {
		return
	}
	if m.columns[m.column].Subgrid {
		m.child = &Model{ctx: m.ctx, host: m.host, columns: []Column{{Name: "Name"}, {Name: "Value"}}, rows: CloneRows(cell.Children), width: m.width, height: m.height, palette: m.palette}
		return
	}
	m.input = strutil.BytesToEscapedStr(cell.Data, false, false)
	m.editing = true
}

func (m *Model) finish() bool {
	if !m.editing {
		return true
	}
	data, err := DecodeEscaped(strings.TrimSpace(m.input))
	if err != nil {
		m.err = err
		return false
	}
	if cell := m.current(); cell != nil {
		cell.Data = data
		m.revision++
	}
	m.editing = false
	m.err = nil
	return true
}

// Load reads into the selected cell outside dispatch and detects stale selection.
func (m *Model) Load(path string, escaped bool) tea.Cmd {
	rev, row, column := m.revision, m.row, m.column
	return func() tea.Msg { data, err := ReadFile(path, escaped); return cellMsg{rev, row, column, data, err} }
}

// Save captures rows and writes the requested CSV outside dispatch.
func (m *Model) Save(path string) tea.Cmd {
	rows := m.Values()
	return func() tea.Msg { return ResultMsg{SaveFile(path, rows)} }
}

// Editor prepares a cancellable external editor for the selected cell.
func (m *Model) Editor() tea.Cmd {
	cell := m.current()
	if cell == nil {
		return nil
	}
	if m.columns[m.column].Subgrid {
		m.err = errors.New("Press enter to edit this field.")
		return nil
	}
	data := bytes.Clone(cell.Data)
	rev, row, column := m.revision, m.row, m.column
	return func() tea.Msg {
		process, err := external.Prepare(m.ctx, external.Request{Data: data})
		return processMsg{rev, row, column, process, err}
	}
}

// Commit validates working rows before making a fresh dispatch edit.
func (m *Model) Commit() tea.Cmd {
	rows := m.Values()
	return func() tea.Msg {
		if m.host == nil {
			return ResultMsg{errors.New("grid has no dispatch host")}
		}
		if m.session != nil {
			edit, err := PrepareRows(m.session, rows)
			if err != nil {
				return ResultMsg{err}
			}
			return ResultMsg{m.host.CommitEdit(m.ctx, edit)}
		}
		args := []any{m.option}
		for _, row := range rows {
			if len(row) > 0 && len(row[0].Data) > 0 {
				args = append(args, string(row[0].Data))
			}
		}
		_, err := m.host.Call(m.ctx, "set", args...)
		return ResultMsg{err}
	}
}

// Update applies admitted commands and consumes editor input before global bindings.
func (m *Model) Update(msg tea.Msg) (tea.Cmd, bool) {
	if m.child != nil {
		if key, ok := msg.(tea.KeyPressMsg); ok && key.String() == "esc" && !m.child.editing {
			if cell := m.current(); cell != nil {
				cell.Children = m.child.Values()
				m.revision++
			}
			m.child = nil
			return nil, true
		}
		return m.child.Update(msg)
	}
	switch msg := msg.(type) {
	case ResultMsg:
		m.err = msg.Err
		return nil, true
	case cellMsg:
		if msg.err != nil {
			m.err = msg.err
			return nil, true
		}
		if msg.revision != m.revision || msg.row != m.row || msg.column != m.column {
			m.err = errors.New("grid cell changed during external work")
			return nil, true
		}
		if cell := m.current(); cell != nil {
			cell.Data = bytes.Clone(msg.data)
			m.revision++
			m.err = nil
		}
		return nil, true
	case processMsg:
		if msg.err != nil {
			m.err = msg.err
			return nil, true
		}
		return msg.process.Tea(func(result external.Result) tea.Msg {
			return cellMsg{msg.revision, msg.row, msg.column, bytes.TrimSuffix(result.Data, []byte("\n")), result.Err}
		}), true
	case Operation:
		switch msg.Name {
		case "add":
			m.Add(false)
		case "insert":
			m.Add(true)
		case "delete":
			m.Delete()
		case "load":
			return m.Load(msg.Path, false), true
		case "load_escaped":
			return m.Load(msg.Path, true), true
		case "save":
			return m.Save(msg.Path), true
		case "editor":
			return m.Editor(), true
		case "commit":
			return m.Commit(), true
		}
		return nil, true
	case tea.KeyPressMsg:
		key := msg.String()
		if m.editing {
			switch key {
			case "esc":
				m.editing = false
				m.err = nil
			case "enter":
				m.finish()
			case "tab":
				if m.finish() {
					m.advance()
					m.begin()
				}
			case "backspace":
				runes := []rune(m.input)
				if len(runes) > 0 {
					m.input = string(runes[:len(runes)-1])
				}
			default:
				m.input += msg.Text
			}
			return nil, true
		}
		switch key {
		case "enter":
			m.begin()
			return nil, true
		case "a":
			m.Add(false)
			return nil, true
		case "A":
			m.Add(true)
			return nil, true
		case "d":
			m.Delete()
			return nil, true
		case "e":
			return m.Editor(), true
		case "tab":
			m.advance()
			return nil, true
		case "left", "h":
			m.column = max(0, m.column-1)
			return nil, true
		case "right", "l":
			m.column = min(len(m.columns)-1, m.column+1)
			return nil, true
		case "up", "k":
			m.row = max(0, m.row-1)
			return nil, true
		case "down", "j":
			m.row = min(max(0, len(m.rows)-1), m.row+1)
			return nil, true
		case "home", "g":
			m.row = 0
			return nil, true
		case "end", "G":
			m.row = max(0, len(m.rows)-1)
			return nil, true
		}
	case tea.MouseClickMsg:
		if msg.Button == tea.MouseLeft && msg.Y > 0 && msg.Y <= len(m.rows) {
			offset := max(0, m.row-max(0, m.height-2)+1)
			m.row = min(len(m.rows)-1, offset+msg.Y-1)
			m.column = min(len(m.columns)-1, msg.X/max(1, m.width/len(m.columns)))
			return nil, true
		}
	}
	return nil, false
}

func (m *Model) advance() {
	if m.column < len(m.columns)-1 {
		m.column++
	} else if m.row < len(m.rows)-1 {
		m.row++
		m.column = 0
	}
}

// View renders only visible rows, accounting for the scroll offset.
func (m *Model) View() string {
	if m.child != nil {
		return m.child.View()
	}
	width := max(1, m.width/max(1, len(m.columns)))
	headings := make([]string, len(m.columns))
	for i, column := range m.columns {
		headings[i] = style.Fit(m.palette.Render("heading", column.Name), width)
	}
	lines := []string{strings.Join(headings, "")}
	if len(m.rows) == 0 {
		lines = append(lines, "No values - you should add some. Press ? for help.")
	}
	start := max(0, m.row-max(0, m.height-3)+1)
	for i := start; i < len(m.rows) && len(lines) < m.height-1; i++ {
		cells := make([]string, len(m.columns))
		for j, cell := range m.rows[i] {
			text := strutil.BytesToEscapedStr(cell.Data, false, false)
			if m.columns[j].Subgrid {
				text = "[attributes]"
			}
			tag := "text"
			if i == m.row && j == m.column {
				tag = "focusfield"
				if m.editing {
					text = m.input
					tag = "editfield"
				}
			}
			cells[j] = style.Fit(m.palette.Render(tag, text), width)
		}
		lines = append(lines, strings.Join(cells, ""))
	}
	if m.err != nil {
		lines = append(lines, m.palette.Render("error", m.err.Error()))
	}
	return strings.Join(lines, "\n")
}
