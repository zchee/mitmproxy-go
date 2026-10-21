// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package keymap

// Defaults returns the source binding table with independent context slices.
func Defaults() []Binding {
	return []Binding{
		{Key: ":", Command: "console.command ", Contexts: []string{"commonkey", "global"}, Help: "Command prompt"},
		{Key: ";", Command: "console.command flow.comment @focus ''", Contexts: []string{"flowlist", "flowview"}, Help: "Add comment to flow"},
		{Key: "?", Command: "console.view.help", Contexts: []string{"global"}, Help: "View help"},
		{Key: "B", Command: "browser.start", Contexts: []string{"global"}, Help: "Start an attached browser"},
		{Key: "C", Command: "console.view.commands", Contexts: []string{"global"}, Help: "View commands"},
		{Key: "K", Command: "console.view.keybindings", Contexts: []string{"global"}, Help: "View key bindings"},
		{Key: "O", Command: "console.view.options", Contexts: []string{"commonkey", "global"}, Help: "View options"},
		{Key: "E", Command: "console.view.eventlog", Contexts: []string{"commonkey", "global"}, Help: "View event log"},
		{Key: "Q", Command: "console.exit", Contexts: []string{"global"}, Help: "Exit immediately"},
		{Key: "q", Command: "console.view.pop", Contexts: []string{"commonkey", "global"}, Help: "Exit the current view"},
		{Key: "esc", Command: "console.view.pop", Contexts: []string{"commonkey", "global"}, Help: "Exit the current view"},
		{Key: "H", Command: "set console_quickhelp_visible toggle", Contexts: []string{"global"}, Help: "Toggle quick help bar visibility"},
		{Key: "-", Command: "console.layout.cycle", Contexts: []string{"global"}, Help: "Cycle to next layout"},
		{Key: "ctrl right", Command: "console.panes.next", Contexts: []string{"global"}, Help: "Focus next layout pane"},
		{Key: "ctrl left", Command: "console.panes.prev", Contexts: []string{"global"}, Help: "Focus previous layout pane"},
		{Key: "shift tab", Command: "console.panes.next", Contexts: []string{"global"}, Help: "Focus next layout pane"},
		{Key: "P", Command: "console.view.flow @focus", Contexts: []string{"global"}, Help: "View flow details"},
		{Key: "?", Command: "console.view.pop", Contexts: []string{"help"}, Help: "Exit help"},
		{Key: "g", Command: "console.nav.start", Contexts: []string{"global"}, Help: "Go to start"},
		{Key: "G", Command: "console.nav.end", Contexts: []string{"global"}, Help: "Go to end"},
		{Key: "k", Command: "console.nav.up", Contexts: []string{"global"}, Help: "Up"},
		{Key: "j", Command: "console.nav.down", Contexts: []string{"global"}, Help: "Down"},
		{Key: "l", Command: "console.nav.right", Contexts: []string{"global"}, Help: "Right"},
		{Key: "h", Command: "console.nav.left", Contexts: []string{"global"}, Help: "Left"},
		{Key: "tab", Command: "console.nav.next", Contexts: []string{"commonkey", "global"}, Help: "Next"},
		{Key: "enter", Command: "console.nav.select", Contexts: []string{"commonkey", "global"}, Help: "Select"},
		{Key: "space", Command: "console.nav.pagedown", Contexts: []string{"global"}, Help: "Page down"},
		{Key: "ctrl f", Command: "console.nav.pagedown", Contexts: []string{"global"}, Help: "Page down"},
		{Key: "ctrl b", Command: "console.nav.pageup", Contexts: []string{"global"}, Help: "Page up"},
		{Key: "I", Command: "set intercept_active toggle", Contexts: []string{"global"}, Help: "Toggle whether the filtering via the intercept option is enabled"},
		{Key: "i", Command: "console.command.set intercept", Contexts: []string{"global"}, Help: "Set intercept"},
		{Key: "W", Command: "console.command.set save_stream_file", Contexts: []string{"global"}, Help: "Stream to file"},
		{Key: "A", Command: "flow.resume @all", Contexts: []string{"flowlist", "flowview"}, Help: "Resume all intercepted flows"},
		{Key: "a", Command: "flow.resume @focus", Contexts: []string{"flowlist", "flowview"}, Help: "Resume this intercepted flow"},
		{Key: "b", Command: "console.command cut.save @focus response.content ", Contexts: []string{"flowlist", "flowview"}, Help: "Save response body to file"},
		{Key: "d", Command: "view.flows.remove @focus", Contexts: []string{"flowlist", "flowview"}, Help: "Delete flow from view"},
		{Key: "D", Command: "view.flows.duplicate @focus", Contexts: []string{"flowlist", "flowview"}, Help: "Duplicate flow"},
		{Key: "x", Command: "\n        console.choose.cmd \"Export as...\" export.formats\n        console.command export.file {choice} @focus\n        ", Contexts: []string{"flowlist", "flowview"}, Help: "Export this flow to file"},
		{Key: "f", Command: "console.command.set view_filter", Contexts: []string{"flowlist"}, Help: "Set view filter"},
		{Key: "F", Command: "set console_focus_follow toggle", Contexts: []string{"flowlist", "flowview"}, Help: "Set focus follow"},
		{Key: "ctrl l", Command: "console.command cut.clip ", Contexts: []string{"flowlist", "flowview"}, Help: "Send cuts to clipboard"},
		{Key: "L", Command: "console.command view.flows.load ", Contexts: []string{"flowlist"}, Help: "Load flows from file"},
		{Key: "m", Command: "flow.mark.toggle @focus", Contexts: []string{"flowlist"}, Help: "Toggle mark on this flow"},
		{Key: "M", Command: "view.properties.marked.toggle", Contexts: []string{"flowlist"}, Help: "Toggle viewing marked flows"},
		{Key: "n", Command: "console.command view.flows.create get https://example.com/", Contexts: []string{"flowlist"}, Help: "Create a new flow"},
		{Key: "o", Command: "\n        console.choose.cmd \"Order flows by...\" view.order.options\n        set view_order {choice}\n        ", Contexts: []string{"flowlist"}, Help: "Set flow list order"},
		{Key: "r", Command: "replay.client @focus", Contexts: []string{"flowlist", "flowview"}, Help: "Replay this flow"},
		{Key: "S", Command: "console.command replay.server ", Contexts: []string{"flowlist"}, Help: "Start server replay"},
		{Key: "v", Command: "set view_order_reversed toggle", Contexts: []string{"flowlist"}, Help: "Reverse flow list order"},
		{Key: "U", Command: "flow.mark @all false", Contexts: []string{"flowlist"}, Help: "Un-set all marks"},
		{Key: "w", Command: "console.command save.file @shown ", Contexts: []string{"flowlist"}, Help: "Save listed flows to file"},
		{Key: "V", Command: "flow.revert @focus", Contexts: []string{"flowlist", "flowview"}, Help: "Revert changes to this flow"},
		{Key: "X", Command: "flow.kill @focus", Contexts: []string{"flowlist"}, Help: "Kill this flow"},
		{Key: "z", Command: "console.command.confirm \"Delete all flows\" view.flows.remove @all", Contexts: []string{"flowlist"}, Help: "Clear flow list"},
		{Key: "Z", Command: "console.command.confirm \"Purge all hidden flows\" view.flows.remove @hidden", Contexts: []string{"flowlist"}, Help: "Purge all flows not showing"},
		{Key: "|", Command: "console.command script.run @focus ", Contexts: []string{"flowlist", "flowview"}, Help: "Run a script on this flow"},
		{Key: "e", Command: "\n        console.choose.cmd \"Edit...\" console.edit.focus.options\n        console.edit.focus {choice}\n        ", Contexts: []string{"flowlist", "flowview"}, Help: "Edit a flow component"},
		{Key: "f", Command: "view.settings.setval.toggle @focus fullcontents", Contexts: []string{"flowview"}, Help: "Toggle viewing full contents on this flow"},
		{Key: "w", Command: "console.command save.file @focus ", Contexts: []string{"flowview"}, Help: "Save flow to file"},
		{Key: "space", Command: "view.focus.next", Contexts: []string{"flowview"}, Help: "Go to next flow"},
		{Key: "v", Command: "\n        console.choose \"View...\" request,response\n        console.bodyview @focus {choice}\n        ", Contexts: []string{"flowview"}, Help: "View flow body in an external viewer"},
		{Key: "p", Command: "view.focus.prev", Contexts: []string{"flowview"}, Help: "Go to previous flow"},
		{Key: "m", Command: "\n        console.choose.cmd \"Set contentview...\" console.flowview.mode.options\n        console.flowview.mode.set {choice}\n        ", Contexts: []string{"flowview"}, Help: "Set flow view mode"},
		{Key: "z", Command: "\n        console.choose \"Encode/decode...\" request,response\n        flow.encode.toggle @focus {choice}\n        ", Contexts: []string{"flowview"}, Help: "Encode/decode flow body"},
		{Key: "L", Command: "console.command options.load ", Contexts: []string{"options"}, Help: "Load from file"},
		{Key: "S", Command: "console.command options.save ", Contexts: []string{"options"}, Help: "Save to file"},
		{Key: "D", Command: "options.reset", Contexts: []string{"options"}, Help: "Reset all options"},
		{Key: "d", Command: "console.options.reset.focus", Contexts: []string{"options"}, Help: "Reset this option"},
		{Key: "a", Command: "console.grideditor.add", Contexts: []string{"grideditor"}, Help: "Add a row after cursor"},
		{Key: "A", Command: "console.grideditor.insert", Contexts: []string{"grideditor"}, Help: "Insert a row before cursor"},
		{Key: "d", Command: "console.grideditor.delete", Contexts: []string{"grideditor"}, Help: "Delete this row"},
		{Key: "r", Command: "console.command console.grideditor.load", Contexts: []string{"grideditor"}, Help: "Read unescaped data into the current cell from file"},
		{Key: "R", Command: "console.command console.grideditor.load_escaped", Contexts: []string{"grideditor"}, Help: "Load a Python-style escaped string into the current cell from file"},
		{Key: "e", Command: "console.grideditor.editor", Contexts: []string{"grideditor"}, Help: "Edit in external editor"},
		{Key: "w", Command: "console.command console.grideditor.save ", Contexts: []string{"grideditor"}, Help: "Save data to file as CSV"},
		{Key: "z", Command: "console.command.confirm \"Clear event log\" eventstore.clear", Contexts: []string{"eventlog"}, Help: "Clear"},
		{Key: "a", Command: "\n        console.choose.cmd \"Context\" console.key.contexts\n        console.command console.key.bind {choice}\n        ", Contexts: []string{"keybindings"}, Help: "Add a key binding"},
		{Key: "d", Command: "console.key.unbind.focus", Contexts: []string{"keybindings"}, Help: "Unbind the currently focused key binding"},
		{Key: "x", Command: "console.key.execute.focus", Contexts: []string{"keybindings"}, Help: "Execute the currently focused key binding"},
		{Key: "enter", Command: "console.key.edit.focus", Contexts: []string{"keybindings"}, Help: "Edit the currently focused key binding"},
	}
}

// NewDefault constructs the upstream keymap and connects its change notification.
func NewDefault(change func()) *Keymap {
	k := New(nil)
	for _, b := range Defaults() {
		if err := k.Add(b); err != nil {
			panic(err)
		}
	}
	k.change = change
	return k
}
