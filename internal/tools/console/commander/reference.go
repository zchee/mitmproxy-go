// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package commander

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// Reference displays owned, current command signatures and their help text.
type Reference struct {
	ctx                  context.Context
	host                 contract.Host
	commands             []contract.Command
	index, width, height int
	help, busy           bool
	pending              []tea.Msg
	err                  error
}

type referenceResult struct {
	owner *Reference
	err   error
}

var _ contract.Widget = (*Reference)(nil)

// NewReference returns a command reference with no registry access during rendering.
func NewReference(ctx context.Context, host contract.Host) *Reference {
	return &Reference{ctx: ctx, host: host, width: 80, height: 24}
}

// SetSnapshot replaces the owned command metadata and authoritative selection.
func (r *Reference) SetSnapshot(s contract.Snapshot) {
	r.commands = slices.Clone(s.Commands)
	slices.SortFunc(r.commands, func(a, b contract.Command) int { return strings.Compare(a.Signature, b.Signature) })
	if w, ok := s.Control.Current("commands", false); ok && !r.busy {
		r.index, r.help = w.Index, w.Column == 1
	}
	r.index = min(max(r.index, 0), max(0, len(r.commands)-1))
}

// Resize changes the visible reference dimensions.
func (r *Reference) Resize(width, height int) { r.width, r.height = max(0, width), max(0, height) }

func (r *Reference) dispatch(action contract.Action) tea.Cmd {
	r.busy = true
	return func() tea.Msg { return referenceResult{owner: r, err: r.host.Dispatch(r.ctx, action)} }
}

// Update returns dispatch work for selection and prompt actions.
func (r *Reference) Update(msg tea.Msg) (cmd tea.Cmd, consumed bool) {
	if result, ok := msg.(referenceResult); ok {
		if result.owner != r {
			return nil, false
		}
		defer func() {
			if result.err != nil {
				cmd = tea.Batch(cmd, func() tea.Msg { return contract.ErrorMsg{Source: "commands", Err: result.err} })
			}
		}()
		r.busy = false
		r.err = result.err
		for len(r.pending) > 0 {
			next := r.pending[0]
			r.pending = r.pending[1:]
			if cmd, _ := r.Update(next); cmd != nil {
				return cmd, true
			}
		}
		return nil, true
	}
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return nil, false
	}
	if r.busy {
		r.pending = append(r.pending, msg)
		return nil, true
	}
	switch key.String() {
	case "up":
		r.index = max(0, r.index-1)
	case "down":
		r.index = min(max(0, len(r.commands)-1), r.index+1)
	case "home":
		r.index = 0
	case "end":
		r.index = max(0, len(r.commands)-1)
	case "tab":
		r.help = !r.help
	case "enter":
		if r.help || len(r.commands) == 0 {
			return nil, true
		}
		text := r.commands[r.index].Name + " "
		return r.dispatch(contract.Action{Kind: "prompt", Value: "command", Text: text, Index: utf8.RuneCountInString(text)}), true
	default:
		return nil, false
	}
	index, column := r.index, 0
	if r.help {
		column = 1
	}
	return r.dispatch(contract.Action{Kind: "selection", Index: index, Column: column}), true
}

// View renders a viewport of signatures and the selected command's help.
func (r *Reference) View() string {
	if r.width == 0 || r.height == 0 {
		return ""
	}
	rows := max(1, r.height-6)
	start := max(0, r.index-rows+1)
	lines := []string{style.Fit("Command Reference", r.width)}
	if r.err != nil {
		lines = append(lines, style.Fit(style.Escape(r.err.Error()), r.width))
	}
	for i := start; i < min(len(r.commands), start+rows); i++ {
		prefix := "   "
		if i == r.index {
			prefix = ">> "
		}
		lines = append(lines, style.Fit(prefix+style.Escape(r.commands[i].Signature), r.width))
	}
	if len(r.commands) > 0 {
		lines = append(lines, style.Fit("Command Help", r.width))
		for line := range strings.SplitSeq(style.Escape(r.commands[r.index].Help), "\n") {
			lines = append(lines, style.Fit(line, r.width))
		}
	}
	return strings.Join(lines[:min(len(lines), r.height)], "\n")
}
