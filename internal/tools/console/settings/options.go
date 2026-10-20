// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package settings implements the console's option and keybinding viewers.
package settings

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
	"github.com/zchee/mitmproxy-go/options"
)

// Options is the registered-option viewer and inline editor.
type Options struct {
	ctx                  context.Context
	host                 contract.Host
	options              []options.Option
	index, width, height int
	help, editing, busy  bool
	editor               commander.Buffer
	editName             string
	pending              []tea.Msg
	err                  error
}

type optionResult struct {
	owner *Options
	err   error
}

var _ contract.Widget = (*Options)(nil)

// NewOptions returns an options viewer whose live work uses the frontend lifetime.
func NewOptions(ctx context.Context, host contract.Host) *Options {
	return &Options{ctx: ctx, host: host, width: 80, height: 24}
}

// SetSnapshot installs detached option metadata and dispatch-authoritative focus.
func (o *Options) SetSnapshot(s contract.Snapshot) {
	o.options = slices.Clone(s.Options)
	slices.SortFunc(o.options, func(a, b options.Option) int { return strings.Compare(a.Name(), b.Name()) })
	if w, ok := s.Control.Current("options", false); ok && !o.busy {
		o.help = w.Column == 1
		if w.Option != "" {
			if i := slices.IndexFunc(o.options, func(option options.Option) bool { return option.Name() == w.Option }); i >= 0 {
				o.index = i
			}
		} else {
			o.index = w.Index
		}
	}
	o.index = min(max(0, o.index), max(0, len(o.options)-1))
}

// Resize changes the option list's available dimensions.
func (o *Options) Resize(width, height int) { o.width, o.height = max(0, width), max(0, height) }

// Error returns the last option validation or dispatch error.
func (o *Options) Error() error { return o.err }

// CurrentName returns the selected registry name, or empty for an empty registry.
func (o *Options) CurrentName() string {
	if len(o.options) == 0 {
		return ""
	}
	return o.options[o.index].Name()
}

func (o *Options) run(work func(context.Context) error) tea.Cmd {
	o.busy = true
	return func() tea.Msg { return optionResult{owner: o, err: work(o.ctx)} }
}

// Update consumes all inline input and returns mutations only as commands.
func (o *Options) Update(msg tea.Msg) (cmd tea.Cmd, consumed bool) {
	if result, ok := msg.(optionResult); ok {
		if result.owner != o {
			return nil, false
		}
		defer func() {
			if result.err != nil {
				cmd = tea.Batch(cmd, func() tea.Msg { return contract.ErrorMsg{Source: "options", Err: result.err} })
			}
		}()
		o.busy = false
		o.err = result.err
		for len(o.pending) > 0 {
			next := o.pending[0]
			o.pending = o.pending[1:]
			if cmd, _ := o.Update(next); cmd != nil {
				return cmd, true
			}
		}
		return nil, true
	}
	switch msg.(type) {
	case tea.KeyPressMsg, tea.PasteMsg:
		if o.busy {
			o.pending = append(o.pending, msg)
			return nil, true
		}
	}
	if paste, ok := msg.(tea.PasteMsg); ok && o.editing {
		o.editor.Insert(paste.Content)
		return nil, true
	}
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return nil, false
	}
	if o.editing {
		switch key.String() {
		case "esc":
			o.editing = false
			o.err = nil
		case "enter":
			name, value := o.editName, o.editor.Text()
			o.editing = false
			return o.run(func(ctx context.Context) error { _, err := o.host.Call(ctx, "set", name, value); return err }), true
		case "backspace":
			o.editor.Backspace()
		case "delete":
			o.editor.Delete()
		case "left", "ctrl+b":
			o.editor.Left()
		case "right", "ctrl+f":
			o.editor.Right()
		case "home", "ctrl+a":
			o.editor.SetCursor(0)
		case "end", "ctrl+e":
			o.editor.SetCursor(len([]rune(o.editor.Text())))
		case "ctrl+w":
			o.editor.DeleteWord()
		default:
			if key.Text != "" {
				o.editor.Insert(key.Text)
			}
		}
		return nil, true
	}
	switch key.String() {
	case "tab":
		o.help = !o.help
	case "home":
		o.index = 0
	case "end":
		o.index = max(0, len(o.options)-1)
	case "up":
		o.index = max(0, o.index-1)
	case "down":
		o.index = min(max(0, len(o.options)-1), o.index+1)
	case "enter":
		if !o.help {
			return o.Select(), true
		}
		return nil, true
	case "d":
		if !o.help {
			return o.Reset(), true
		}
		return nil, false
	default:
		return nil, false
	}
	name, index, column := o.CurrentName(), o.index, 0
	if o.help {
		column = 1
	}
	return o.run(func(ctx context.Context) error {
		return o.host.Do(ctx, func(ctx context.Context) error {
			if err := o.host.Dispatch(ctx, contract.Action{Kind: "selection", Index: index, Column: column}); err != nil {
				return err
			}
			return o.host.Dispatch(ctx, contract.Action{Kind: "option", Value: name})
		})
	}), true
}

// Select toggles a boolean or opens the appropriate inline, choice or grid editor.
func (o *Options) Select() tea.Cmd {
	if len(o.options) == 0 {
		return nil
	}
	option := o.options[o.index]
	name := option.Name()
	if option.Type() == options.TypeBool {
		return o.run(func(ctx context.Context) error { _, err := o.host.Call(ctx, "set", name, "toggle"); return err })
	}
	if choices := option.Choices(); len(choices) > 0 {
		return o.run(func(ctx context.Context) error {
			return o.host.Dispatch(ctx, commander.ChoicePrompt(name, choices, "set", []string{name, "{choice}"}))
		})
	}
	if option.Type() == options.TypeSeq {
		values := option.Current().([]string)
		rows := make([][]string, len(values))
		for i, value := range values {
			rows[i] = []string{value}
		}
		return o.run(func(ctx context.Context) error {
			return o.host.OpenGrid(ctx, contract.GridRequest{Title: name, Option: name, Rows: rows})
		})
	}
	o.editing = true
	o.editName = name
	o.editor = commander.NewBuffer(displayValue(option.Current()))
	o.err = nil
	return nil
}

// Reset applies the selected option's registered default using the existing set command.
func (o *Options) Reset() tea.Cmd {
	if len(o.options) == 0 {
		return nil
	}
	option := o.options[o.index]
	args := []any{option.Name()}
	switch value := option.Default().(type) {
	case []string:
		for _, item := range value {
			args = append(args, item)
		}
	case *string:
		if value != nil {
			args = append(args, *value)
		}
	case *int:
		if value != nil {
			args = append(args, strconv.Itoa(*value))
		}
	default:
		args = append(args, displayValue(value))
	}
	return o.run(func(ctx context.Context) error { _, err := o.host.Call(ctx, "set", args...); return err })
}

// View renders only the visible option rows and selected help text.
func (o *Options) View() string {
	if o.width == 0 || o.height == 0 {
		return ""
	}
	rows := max(1, o.height-6)
	start := max(0, o.index-rows+1)
	nameWidth := 0
	for _, option := range o.options {
		nameWidth = max(nameWidth, style.Width(option.Name()))
	}
	nameWidth = min(nameWidth, max(0, o.width/2))
	lines := []string{style.Fit("Options", o.width)}
	for i := start; i < min(len(o.options), start+rows); i++ {
		option := o.options[i]
		prefix := "  "
		if i == o.index {
			prefix = "> "
		}
		if option.HasChanged() {
			prefix = prefix[:1] + "*"
		}
		value := displayValue(option.Current())
		if option.Type() == options.TypeSeq {
			value = pyrepr.Value(option.Current())
		}
		if o.editing && option.Name() == o.editName {
			value = o.editor.Text()
		}
		lines = append(lines, style.Fit(prefix+style.Fit(style.Escape(option.Name()), nameWidth)+"  "+style.Escape(value), o.width))
	}
	if o.err != nil {
		lines = append(lines, style.Fit(style.Escape(o.err.Error()), o.width))
	}
	if len(o.options) > 0 {
		lines = append(lines, style.Fit("Option Help", o.width))
		for line := range strings.SplitSeq(style.Escape(o.options[o.index].Help()), "\n") {
			lines = append(lines, style.Fit(line, o.width))
		}
	}
	return strings.Join(lines[:min(len(lines), o.height)], "\n")
}

func displayValue(value any) string {
	switch value := value.(type) {
	case nil:
		return ""
	case *string:
		if value == nil {
			return ""
		}
		return *value
	case *int:
		if value == nil {
			return ""
		}
		return strconv.Itoa(*value)
	default:
		return fmt.Sprint(value)
	}
}
