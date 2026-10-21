// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

type resultWidget struct {
	host    *Bridge
	view    viewport.Model
	text    string
	width   int
	palette style.Palette
}

func newResultWidget(host *Bridge, text string) *resultWidget {
	v := viewport.New()
	v.KeyMap = viewport.KeyMap{}
	v.MouseWheelEnabled = false
	return &resultWidget{host: host, view: v, text: style.Escape(text)}
}

func (w *resultWidget) SetSnapshot(snapshot contract.Snapshot) {
	name, transparent := "solarized_dark", true
	for _, option := range snapshot.Options {
		switch option.Name() {
		case "console_palette":
			name, _ = option.Current().(string)
		case "console_palette_transparent":
			transparent, _ = option.Current().(bool)
		}
	}
	w.palette, _ = style.NewPalette(name, transparent)
}

func (w *resultWidget) Resize(width, height int) {
	w.width = max(0, width)
	w.view.SetWidth(max(0, width*4/5-2))
	w.view.SetHeight(max(0, height-2))
	lines := strings.Split(w.text, "\n")
	for i := range lines {
		lines[i] = style.Fit(lines[i], w.view.Width())
	}
	w.view.SetContent(strings.Join(lines, "\n"))
}

func (w *resultWidget) Update(message tea.Msg) (tea.Cmd, bool) {
	switch message := message.(type) {
	case contract.Action:
		if message.Kind != "nav" {
			return nil, false
		}
		switch message.Value {
		case "start":
			w.view.GotoTop()
		case "end":
			w.view.GotoBottom()
		case "up":
			w.view.ScrollUp(1)
		case "down":
			w.view.ScrollDown(1)
		case "pageup":
			w.view.PageUp()
		case "pagedown":
			w.view.PageDown()
		}
		return nil, true
	case tea.KeyPressMsg:
		directions := map[string]string{"up": "up", "down": "down", "home": "start", "end": "end", "pgup": "pageup", "pgdown": "pagedown"}
		direction, ok := directions[message.String()]
		if !ok || w.host == nil {
			return nil, false
		}
		return func() tea.Msg {
			err := w.host.Dispatch(w.host.Context(), contract.Action{Kind: "nav", Value: direction})
			if err != nil {
				return contract.ErrorMsg{Source: "dataviewer", Err: err}
			}
			return nil
		}, true
	}
	return nil, false
}

func (w *resultWidget) View() string {
	if w.width <= 0 {
		return ""
	}
	border := lipgloss.NormalBorder()
	box := lipgloss.NewStyle().Border(border).BorderForeground(w.palette.Style("heading").GetForeground()).Render(w.view.View())
	lines := strings.Split(box, "\n")
	title := " Data viewer "
	title = style.Fit(title, min(style.Width(title), w.view.Width()))
	lines[0] = w.palette.Style("heading").Render(border.TopLeft + title + strings.Repeat(border.Top, max(0, w.view.Width()-style.Width(title))) + border.TopRight)
	return lipgloss.PlaceHorizontal(w.width, lipgloss.Center, strings.Join(lines, "\n"))
}
