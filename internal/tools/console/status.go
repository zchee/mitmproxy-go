// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

type helpItem struct{ short, help, key string }

// QuickHelp returns the two context-sensitive, cell-clipped help rows.
func QuickHelp(state contract.State, snapshot contract.Snapshot, width int) [2]string {
	window, _ := state.Current("", true)
	var items []helpItem
	label := ""
	add := func(short, help string) { items = append(items, helpItem{short: short, help: help}) }
	basic := func(short, key string) { items = append(items, helpItem{short: short, key: key}) }
	focused := snapshot.Focused
	switch window.Context {
	case "flowlist", "flowview":
		label = "Flow:"
		if focused != nil {
			if window.Context == "flowlist" {
				add("Select", "Select")
			} else {
				add("Edit", "Edit a flow component")
			}
			add("Duplicate", "Duplicate flow")
			add("Replay", "Replay this flow")
			add("Export", "Export this flow to file")
			add("Delete", "Delete flow from view")
			if window.Context == "flowlist" {
				if focused.Common().Marked != "" {
					add("Unmark", "Toggle mark on this flow")
				} else {
					add("Mark", "Toggle mark on this flow")
				}
				add("Edit", "Edit a flow component")
			}
			if focused.Common().Intercepted() {
				add("Resume", "Resume this intercepted flow")
			}
			if focused.Modified() {
				add("Restore", "Revert changes to this flow")
			}
			if f, ok := focused.(*flow.HTTPFlow); ok && f.Response != nil {
				add("Save body", "Save response body to file")
			}
			if window.Context == "flowview" {
				add("Next flow", "Go to next flow")
				add("Prev flow", "Go to previous flow")
			}
		} else {
			add("Load flows", "Load flows from file")
			add("Create new", "Create a new flow")
		}
	case "keybindings":
		label = "Keybindings:"
		add("Add", "Add a key binding")
		add("Edit", "Edit the currently focused key binding")
		add("Delete", "Unbind the currently focused key binding")
		add("Execute", "Execute the currently focused key binding")
	case "options":
		label = "Options:"
		basic("Edit", "⏎")
		add("Reset", "Reset this option")
		add("Reset all", "Reset all options")
		add("Load file", "Load from file")
		add("Save file", "Save to file")
	case "help":
		label = "Help:"
		basic("Scroll down", "↓")
		basic("Scroll up", "↑")
		add("Exit help", "Exit help")
		basic("Next tab", "tab")
	case "eventlog":
		label = "Events:"
		basic("Scroll down", "↓")
		basic("Scroll up", "↑")
		add("Clear", "Clear")
	case "grideditor":
		label = "Edit:"
		basic("Start edit", "⏎")
		basic("Stop edit", "esc")
		add("Add row", "Add a row after cursor")
		add("Delete row", "Delete this row")
	}
	bottom := []helpItem{{short: "Help", help: "View help"}}
	back := "Back"
	if len(state.Panes[state.Pane].Stack) == 1 {
		back = "Quit"
	}
	bottom = append(bottom, helpItem{short: back, help: "Exit the current view"}, helpItem{short: "Events", help: "View event log"}, helpItem{short: "Options", help: "View options"}, helpItem{short: "Intercept", help: "Set intercept"}, helpItem{short: "Filter", help: "Set view filter"})
	if focused != nil {
		bottom = append(bottom, helpItem{short: "Save flows", help: "Save listed flows to file"}, helpItem{short: "Clear list", help: "Clear flow list"})
	}
	bottom = append(bottom, helpItem{short: "Layout", help: "Cycle to next layout"}, helpItem{short: "Switch", help: "Focus next layout pane"}, helpItem{short: "Follow new", help: "Set focus follow"})
	labelWidth := max(style.Width(label), 9)
	return [2]string{helpRow(label, items, snapshot.Bindings, labelWidth, width), helpRow("Proxy:", bottom, snapshot.Bindings, labelWidth, width)}
}

func helpRow(label string, items []helpItem, bindings []contract.Binding, labelWidth, width int) string {
	var row strings.Builder
	row.WriteString(style.Fit(label, labelWidth))
	for _, item := range items {
		key := item.key
		if key == "" {
			for _, b := range bindings {
				if b.Help == item.help {
					key = (keymap.Binding{Key: b.Key}).KeyShort()
					break
				}
			}
		}
		if key != "" {
			row.WriteString(style.Fit(style.Escape(key+" "+item.short), 14))
		}
	}
	return style.Fit(row.String(), width)
}

// StatusLine renders only captured values; it never reads a live store or option.
func StatusLine(snapshot contract.Snapshot, width int) string {
	arrow := "⇩"
	if snapshot.Status.Reverse {
		arrow = "⇧"
	}
	marked := ""
	if snapshot.Status.Marked {
		marked = "M"
	}
	left := fmt.Sprintf("%s %s [%d/%d]", arrow, marked, max(snapshot.FocusIndex+1, 0), snapshot.Total)
	left = style.Fit(left, 11) + style.Escape(snapshot.Status.Indicators)
	right := ""
	if len(snapshot.Status.Listeners) > 0 {
		right = "[" + style.Escape(strings.Join(snapshot.Status.Listeners, ", ")) + "]"
	}
	if style.Width(right) >= width {
		return style.Fit(right, width)
	}
	return style.Fit(left, width-style.Width(right)) + right
}

// ShortenMessage preserves the event-log hint while clipping a message to one row.
func ShortenMessage(message string, width int) string {
	message = style.Escape(message)
	first, _, multiline := strings.Cut(message, "\n")
	hint := "(more in eventlog)"
	if !multiline && style.Width(first) <= width {
		return first
	}
	room := max(0, width-style.Width(hint))
	if style.Width(first) > room {
		first = style.Truncate(first, max(1, room))
	}
	return first + hint
}
