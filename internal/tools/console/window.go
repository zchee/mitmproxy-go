// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"slices"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"

	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// Rect locates one pane's content after headers and the shared footer are removed.
type Rect struct{ X, Y, Width, Height int }

// Layout returns the content rectangles for the visible panes.
func Layout(state contract.State, width, height, footer int) []Rect {
	width, height = max(0, width), max(0, height-footer)
	header := 0
	if state.Headers {
		header = 1
	}
	switch state.Layout {
	case "vertical":
		top := (height + 1) / 2
		return []Rect{{Y: min(header, top), Width: width, Height: max(0, top-header)}, {Y: top + min(header, height-top), Width: width, Height: max(0, height-top-header)}}
	case "horizontal":
		left := max(0, width-1+1) / 2
		return []Rect{{Y: min(header, height), Width: left, Height: max(0, height-header)}, {X: min(width, left+1), Y: min(header, height), Width: max(0, width-left-1), Height: max(0, height-header)}}
	default:
		return []Rect{{Y: min(header, height), Width: width, Height: max(0, height-header)}}
	}
}

// Hit locates a content cell and applies that pane's scroll offset.
// Headers, the divider and footer never resolve to a content row.
func Hit(rects []Rect, x, y int, scroll [2]int) (pane, column, row int, ok bool) {
	for i, r := range rects {
		if x >= r.X && x < r.X+r.Width && y >= r.Y && y < r.Y+r.Height {
			return i, x - r.X, y - r.Y + scroll[i], true
		}
	}
	return 0, 0, 0, false
}

// Compose lays out already-rendered pane contents without accessing live state.
func Compose(state contract.State, panes []string, width, height int, footer []string) string {
	rects := Layout(state, width, height, len(footer))
	rendered := make([]string, len(rects))
	for i, r := range rects {
		content := ""
		if i < len(panes) {
			content = panes[i]
		}
		lines := strings.Split(content, "\n")
		for len(lines) < r.Height {
			lines = append(lines, "")
		}
		lines = lines[:r.Height]
		for j := range lines {
			lines[j] = style.Fit(lines[j], r.Width)
		}
		if state.Headers {
			p := state.Panes[i]
			title := ""
			if len(p.Stack) > 0 {
				title = p.Stack[len(p.Stack)-1].Title
			}
			lines = append([]string{style.Fit(style.Escape(title), r.Width)}, lines...)
		}
		rendered[i] = strings.Join(lines, "\n")
	}
	body := ""
	if len(rendered) == 1 {
		body = rendered[0]
	} else if state.Layout == "horizontal" {
		body = lipgloss.JoinHorizontal(lipgloss.Top, rendered[0], " ", rendered[1])
	} else {
		body = strings.Join(rendered, "\n")
	}
	if len(footer) > 0 {
		body += "\n" + strings.Join(footer, "\n")
	}
	lines := strings.Split(body, "\n")
	for len(lines) < height {
		lines = append(lines, "")
	}
	lines = lines[:max(0, height)]
	for i := range lines {
		lines[i] = style.Fit(lines[i], width)
	}
	return strings.Join(lines, "\n")
}

// HelpWidget is the current-keymap and filter reference with independent scrolling.
type HelpWidget struct {
	viewport viewport.Model
	snapshot contract.Snapshot
	tab      int
	context  string
}

// NewHelpWidget creates a help viewer for the calling view's key context.
func NewHelpWidget(context string) *HelpWidget {
	v := viewport.New()
	v.KeyMap = viewport.KeyMap{}
	v.MouseWheelEnabled = false
	return &HelpWidget{viewport: v, context: context}
}

// SetSnapshot replaces owned help data and refreshes the active tab.
func (h *HelpWidget) SetSnapshot(snapshot contract.Snapshot) { h.snapshot = snapshot; h.render() }

// Resize updates the help's visible dimensions.
func (h *HelpWidget) Resize(width, height int) {
	h.viewport.SetWidth(width)
	h.viewport.SetHeight(height)
	h.render()
}

func (h *HelpWidget) render() {
	var lines []string
	if h.tab == 0 {
		for _, section := range []struct{ title, context string }{{"Common Keybindings", "commonkey"}, {"Keybindings for this view", h.context}, {"Global Keybindings", "global"}} {
			lines = append(lines, section.title)
			for _, b := range h.snapshot.Bindings {
				found := slices.Contains(b.Contexts, section.context)
				if !found {
					continue
				}
				help := b.Help
				if help == "" {
					help = b.Command
				}
				lines = append(lines, style.Escape(b.Key+"  "+help))
			}
			lines = append(lines, "")
		}
	} else {
		lines = append(lines, "Filter Expressions")
		for _, entry := range filter.Help() {
			lines = append(lines, style.Escape(entry.Expr+"  "+entry.Help))
		}
		lines = append(lines, "", "Regexes are Python-style.", "Regexes can be specified as quoted strings.", "Header matching (~h, ~hq, ~hs) is against name: value.", "Expressions with no operators match the URL.", "Default binary operator is &.")
	}
	h.viewport.SetContent(strings.Join(lines, "\n"))
}

// Update handles reference navigation without dispatch or default shortcut clashes.
func (h *HelpWidget) Update(msg tea.Msg) (tea.Cmd, bool) {
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return nil, false
	}
	switch key.String() {
	case "tab":
		h.tab = 1 - h.tab
		h.viewport.GotoTop()
		h.render()
	case "j", "down":
		h.viewport.ScrollDown(1)
	case "k", "up":
		h.viewport.ScrollUp(1)
	case "g", "home":
		h.viewport.GotoTop()
	case "G", "end":
		h.viewport.GotoBottom()
	case "pgdown", "space":
		h.viewport.PageDown()
	case "pgup":
		h.viewport.PageUp()
	default:
		return nil, false
	}
	return nil, true
}

// View renders only owned help text.
func (h *HelpWidget) View() string { return h.viewport.View() }
