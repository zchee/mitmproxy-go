// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package flowlist composes a virtualized viewport over the authoritative view.
package flowlist

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

type rowFormatter func(flow.Flow, contract.ProjectionRequest, bool) contract.Row

// Project extracts owned visible rows from one dispatch-protected view traversal.
func Project(flows []flow.Flow, request contract.ProjectionRequest) contract.Projection {
	return project(flows, request, formatRow)
}

func formatRow(f flow.Flow, request contract.ProjectionRequest, focused bool) contract.Row {
	return style.FormatFlow(f, request.Layout, request.ShowHost, request.Viewport.Width, focused)
}

func project(flows []flow.Flow, request contract.ProjectionRequest, format rowFormatter) contract.Projection {
	result := contract.Projection{Total: len(flows), FocusIndex: -1, IDs: make([]string, len(flows))}
	for index, f := range flows {
		id := strings.Clone(f.Common().ID)
		result.IDs[index] = id
		if id == request.FocusID {
			result.FocusIndex, result.FocusID = index, id
		}
	}
	if len(flows) == 0 || request.Viewport.Height <= 0 || request.Viewport.Width <= 0 {
		return result
	}
	first := min(max(request.Viewport.Offset, 0), len(flows)-1)
	if result.FocusIndex >= 0 {
		if result.FocusIndex < first {
			first = result.FocusIndex
		} else {
			used := 0
			for index := first; index <= result.FocusIndex && used <= request.Viewport.Height; index++ {
				used += flowHeight(flows[index], request.Layout, request.Viewport.Width)
			}
			if used > request.Viewport.Height {
				first, used = result.FocusIndex, flowHeight(flows[result.FocusIndex], request.Layout, request.Viewport.Width)
				for first > 0 {
					height := flowHeight(flows[first-1], request.Layout, request.Viewport.Width)
					if used+height > request.Viewport.Height {
						break
					}
					first--
					used += height
				}
			}
		}
	}
	result.FirstIndex = first
	result.Rows = make([]contract.Row, 0, min(len(flows)-first, request.Viewport.Height))
	used := 0
	for index := first; index < len(flows) && used < request.Viewport.Height; index++ {
		result.Rows = append(result.Rows, format(flows[index], request, index == result.FocusIndex))
		used += flowHeight(flows[index], request.Layout, request.Viewport.Width)
	}
	return result
}

func flowHeight(f flow.Flow, layout string, width int) int {
	if _, ok := f.(*flow.HTTPFlow); ok && (layout == "list" || layout == "default" && width < 100 || layout == "" && width < 100) {
		return 2
	}
	return 1
}

type visibleRow struct {
	id                   string
	index, first, height int
}

// Model retains only owned visible rows and viewport coordinates.
type Model struct {
	ctx                 context.Context
	host                contract.Host
	viewport            viewport.Model
	request             contract.Viewport
	rows                []visibleRow
	first, focus, total int
	mouse               bool
}

// New constructs a flow-list widget using the frontend's lifetime context.
func New(ctx context.Context, host contract.Host) *Model {
	return &Model{ctx: ctx, host: host, viewport: viewport.New(), focus: -1}
}

// Resize requests a snapshot at the new physical viewport dimensions.
func (m *Model) Resize(width, height int) {
	width, height = max(0, width), max(0, height)
	if m.request.Width == width && m.request.Height == height {
		return
	}
	m.viewport.SetWidth(width)
	m.viewport.SetHeight(height)
	m.request.Width, m.request.Height = width, height
	m.request.Revision++
	m.host.RequestViewport(m.request)
}

// SetSnapshot installs only the visible, already-formatted flow projection.
func (m *Model) SetSnapshot(snapshot contract.Snapshot) {
	m.first, m.focus, m.total = snapshot.FirstIndex, snapshot.FocusIndex, snapshot.Total
	m.mouse = snapshot.Control.Mouse
	m.request.Offset = snapshot.FirstIndex
	m.rows = m.rows[:0]
	lines := make([]string, 0, m.viewport.Height())
	for index, row := range snapshot.Rows {
		if len(lines) >= m.viewport.Height() {
			break
		}
		parts := strings.Split(row.Text, "\n")
		parts = parts[:min(len(parts), m.viewport.Height()-len(lines))]
		m.rows = append(m.rows, visibleRow{id: row.ID, index: snapshot.FirstIndex + index, first: len(lines), height: len(parts)})
		for _, line := range parts {
			lines = append(lines, style.Fit(line, m.viewport.Width()))
		}
	}
	m.viewport.SetContent(strings.Join(lines, "\n"))
	m.viewport.SetYOffset(0)
}

// Update handles list navigation; other keys remain available to the keymap.
// Mouse coordinates must be relative to the body after pane/header offsets.
func (m *Model) Update(message tea.Msg) (tea.Cmd, bool) {
	direction, clickedID := "", ""
	accepted := false
	switch message := message.(type) {
	case contract.Action:
		if message.Kind != "nav" {
			return nil, false
		}
		direction, accepted = message.Value, true
	case tea.KeyPressMsg:
		switch message.String() {
		case "up":
			direction = "up"
		case "down":
			direction = "down"
		case "home":
			direction = "start"
		case "end":
			direction = "end"
		case "pgup":
			direction = "pageup"
		case "pgdown":
			direction = "pagedown"
		case "enter":
			direction = "select"
		default:
			return nil, false
		}
	case tea.MouseClickMsg:
		if !m.mouse || message.Button != tea.MouseLeft {
			return nil, false
		}
		index, ok := m.hit(message.X, message.Y)
		if !ok {
			return nil, false
		}
		clickedID = m.rows[index-m.first].id
	case tea.MouseWheelMsg:
		if !m.mouse {
			return nil, false
		}
		switch message.Button {
		case tea.MouseWheelUp:
			direction = "up"
		case tea.MouseWheelDown:
			direction = "down"
		default:
			return nil, false
		}
	default:
		return nil, false
	}
	if m.total == 0 {
		return nil, true
	}
	pageSize := max(1, len(m.rows))
	return func() tea.Msg {
		if !accepted && clickedID == "" {
			if err := m.host.Dispatch(m.ctx, contract.Action{Kind: "nav", Value: direction}); err != nil {
				return contract.ErrorMsg{Source: "flowlist", Err: err}
			}
			return nil
		}
		err := m.host.Do(m.ctx, func(ctx context.Context) error {
			if clickedID != "" {
				value, err := m.host.Call(ctx, "view.flows.resolve", "@shown")
				if err != nil {
					return err
				}
				flows, ok := value.([]flow.Flow)
				if !ok {
					return fmt.Errorf("invalid flow view result")
				}
				index := slices.IndexFunc(flows, func(f flow.Flow) bool { return f.Common().ID == clickedID })
				if index < 0 {
					return fmt.Errorf("selected flow is no longer visible")
				}
				if _, err := m.host.Call(ctx, "view.focus.go", index); err != nil {
					return err
				}
				direction = "select"
			}
			switch direction {
			case "start", "end":
				offset := 0
				if direction == "end" {
					offset = -1
				}
				_, err := m.host.Call(ctx, "view.focus.go", offset)
				return err
			case "up", "down", "pageup", "pagedown":
				command, count := "view.focus.next", 1
				if direction == "up" || direction == "pageup" {
					command = "view.focus.prev"
				}
				if direction == "pageup" || direction == "pagedown" {
					count = pageSize
				}
				for range count {
					if _, err := m.host.Call(ctx, command); err != nil {
						return err
					}
				}
			case "select":
				_, err := m.host.Execute(ctx, "console.view.flow @focus")
				return err
			}
			return nil
		})
		if err != nil {
			return contract.ErrorMsg{Source: "flowlist", Err: err}
		}
		return nil
	}, true
}

func (m *Model) hit(x, y int) (int, bool) {
	if x < 0 || x >= m.viewport.Width() {
		return 0, false
	}
	row := slices.IndexFunc(m.rows, func(row visibleRow) bool { return y >= row.first && y < row.first+row.height })
	if row < 0 {
		return 0, false
	}
	return m.rows[row].index, true
}

// View renders the current owned viewport without traversing the flow store.
func (m *Model) View() string { return m.viewport.View() }

var _ contract.Widget = (*Model)(nil)
