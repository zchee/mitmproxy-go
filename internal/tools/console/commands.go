// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
)

func (a *ConsoleAddon) registerCommands(loader *addon.Loader) error {
	for _, spec := range []struct {
		name, help string
		fn         any
		params     []string
		choice     string
	}{
		{"console.layout.options", "Returns the available options for the console_layout option.", a.layoutOptions, nil, ""},
		{"console.layout.cycle", "Cycle through the console layout options.", a.layoutCycle, nil, ""},
		{"console.panes.next", "Go to the next layout pane.", a.paneNext, nil, ""},
		{"console.panes.prev", "Go to the previous layout pane.", a.paneNext, nil, ""},
		{"console.options.reset.focus", "Reset the current option in the options editor.", a.resetOption, nil, ""},
		{"console.choose", "Prompt the user to choose from a specified list of strings, then invoke another command with all occurrences of {choice} replaced by the choice the user made.", a.choose, []string{"prompt", "choices", "cmd", "args"}, ""},
		{"console.choose.cmd", "Prompt the user to choose from a list of strings returned by a command, then invoke another command with all occurrences of {choice} replaced by the choice the user made.", a.chooseCommand, []string{"prompt", "choicecmd", "subcmd", "args"}, ""},
		{"console.command", "Prompt the user to edit a command with a (possibly empty) starting value.", a.commandPrompt, []string{"command_str"}, ""},
		{"console.command.confirm", "Prompt the user before running the specified command.", a.confirm, []string{"prompt", "cmd", "args"}, ""},
		{"console.command.set", "Prompt the user to set an option.", a.setPrompt, []string{"option_name"}, ""},
		{"console.view.flow", "View a flow.", a.viewFlow, []string{"flow"}, ""},
		{"console.exit", "Exit mitmproxy.", a.exit, nil, ""},
		{"console.view.pop", "Pop a view off the console stack. At the top level, this prompts the user to exit mitmproxy.", a.pop, nil, ""},
		{"console.flowview.mode.set", "Set the display mode for the current flow view.", a.setMode, []string{"mode"}, "console.flowview.mode.options"},
		{"console.flowview.mode.options", "Returns the valid options for the flowview mode.", a.modeOptions, nil, ""},
		{"console.flowview.mode", "Get the display mode for the current flow view.", a.mode, nil, ""},
		{"console.key.contexts", "The available contexts for key binding.", a.keyContexts, nil, ""},
		{"console.key.bind", "Bind a shortcut key.", a.bind, []string{"contexts", "key", "cmd", "args"}, ""},
		{"console.key.unbind", "Un-bind a shortcut key.", a.unbind, []string{"contexts", "key"}, ""},
		{"console.key.unbind.focus", "Un-bind the shortcut key currently focused in the key binding viewer.", a.unbindFocus, nil, ""},
		{"console.key.execute.focus", "Execute the currently focused key binding.", a.executeBinding, nil, ""},
		{"console.key.edit.focus", "Execute the currently focused key binding.", a.editBinding, nil, ""},
	} {
		opts := []command.Option{command.WithHelp(spec.help), command.WithParams(spec.params...)}
		if spec.choice != "" {
			opts = append(opts, command.WithArgument(spec.params[0], command.Choice(spec.choice)))
		}
		if err := loader.AddCommand(spec.name, spec.fn, opts...); err != nil {
			return err
		}
	}
	for _, spec := range []struct{ direction, help string }{
		{"start", "Go to the start of a list or scrollable."},
		{"end", "Go to the end of a list or scrollable."},
		{"next", "Go to the next navigatable item."},
		{"select", "Select a navigable item for viewing or editing."},
		{"up", "Go up."},
		{"down", "Go down."},
		{"pageup", "Go up."},
		{"pagedown", "Go down."},
		{"left", "Go left."},
		{"right", "Go right."},
	} {
		if err := loader.AddCommand("console.nav."+spec.direction, func(ctx context.Context) error {
			return a.bridge.Dispatch(ctx, contract.Action{Kind: "nav", Value: spec.direction})
		}, command.WithHelp(spec.help)); err != nil {
			return err
		}
	}
	for _, spec := range []struct{ name, title, help string }{
		{"keybindings", "Key Bindings", "View the commands list."},
		{"commands", "Command Reference", "View the commands list."},
		{"options", "Options", "View the options editor."},
		{"eventlog", "Events", "View the event log."},
		{"help", "Help", "View help."},
	} {
		if err := loader.AddCommand("console.view."+spec.name, func(ctx context.Context) error {
			window := contract.Window{Name: spec.name, Title: spec.title, Context: spec.name}
			if spec.name == "options" {
				keys := a.bridge.cfg.Master.Options.Keys()
				slices.Sort(keys)
				if len(keys) != 0 {
					window.Option = keys[0]
				}
			}
			if spec.name == "keybindings" {
				bindings := a.bridge.Keys.Snapshot()
				if len(bindings) != 0 {
					window.Binding = bindings[0].Key + "@" + strings.Join(bindings[0].Contexts, ",")
				}
			}
			return a.bridge.Dispatch(ctx, contract.Action{Kind: "push", Window: window})
		}, command.WithHelp(spec.help)); err != nil {
			return err
		}
	}
	return a.registerEditing(loader)
}

func (a *ConsoleAddon) layoutOptions(context.Context) []string {
	return []string{"single", "vertical", "horizontal"}
}

func (a *ConsoleAddon) layoutCycle(ctx context.Context) error {
	layouts := a.layoutOptions(ctx)
	current := a.bridge.cfg.Master.Options.Str("console_layout")
	next := layouts[(slices.Index(layouts, current)+1)%len(layouts)]
	return a.bridge.Control.Apply(ctx, contract.Action{Kind: "edited"}, func(ctx context.Context) error {
		return a.bridge.cfg.Master.Options.Update(ctx, map[string]any{"console_layout": next})
	})
}

func (a *ConsoleAddon) paneNext(ctx context.Context) error {
	return a.bridge.Dispatch(ctx, contract.Action{Kind: "pane"})
}

func (a *ConsoleAddon) resetOption(ctx context.Context) error {
	window, ok := a.bridge.Control.State().Current("options", true)
	if !ok {
		return errors.New("Not viewing options.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	return a.bridge.Control.Apply(ctx, contract.Action{Kind: "edited"}, func(ctx context.Context) error {
		_, err := a.bridge.cfg.Master.Call(ctx, "options.reset.one", window.Option)
		return err
	})
}

func (a *ConsoleAddon) choose(ctx context.Context, prompt string, choices []string, cmd command.Cmd, args ...command.CmdArgs) error {
	return a.bridge.Dispatch(ctx, commander.ChoicePrompt(prompt, choices, string(cmd), commandArguments(args)))
}

func (a *ConsoleAddon) chooseCommand(ctx context.Context, prompt string, choicecmd, subcmd command.Cmd, args ...command.CmdArgs) error {
	value, err := a.bridge.cfg.Master.Commands.Execute(ctx, string(choicecmd))
	if err != nil {
		return err
	}
	choices, ok := value.([]string)
	if !ok {
		return fmt.Errorf("choice command returned %T, expected strings", value)
	}
	return a.bridge.Dispatch(ctx, commander.ChoicePrompt(prompt, choices, string(subcmd), commandArguments(args)))
}

func commandArguments(args []command.CmdArgs) []string {
	values := make([]string, len(args))
	for i, arg := range args {
		values[i] = string(arg)
	}
	return values
}

func (a *ConsoleAddon) commandPrompt(ctx context.Context, arguments ...string) error {
	return a.bridge.Dispatch(ctx, commander.CommandPrompt(arguments...))
}

func (a *ConsoleAddon) confirm(ctx context.Context, prompt string, cmd command.Cmd, args ...command.CmdArgs) error {
	return a.bridge.Dispatch(ctx, commander.ConfirmPrompt(prompt, string(cmd), commandArguments(args)))
}

func (a *ConsoleAddon) setPrompt(ctx context.Context, name string) error {
	option, ok := a.bridge.cfg.Master.Options.Lookup(name)
	if !ok {
		return fmt.Errorf("unknown option: %s", name)
	}
	return a.bridge.Dispatch(ctx, commander.OptionPrompt(option))
}

func (a *ConsoleAddon) viewFlow(ctx context.Context, f flow.Flow) error {
	if f == nil {
		return errors.New("No flow selected.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	return a.bridge.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "flowview", Title: "Flow Details", Context: "flowview", FlowID: f.Common().ID}})
}

func (a *ConsoleAddon) exit(ctx context.Context) error {
	return a.bridge.Control.Apply(ctx, contract.Action{Kind: "edited"}, func(context.Context) error {
		a.bridge.cfg.Master.Shutdown()
		return nil
	})
}

func (a *ConsoleAddon) pop(ctx context.Context) error {
	window, _ := a.bridge.Control.State().Current("", true)
	if window.Context == "grideditor" {
		return a.bridge.Dispatch(ctx, contract.Action{Kind: "grid", Value: "commit"})
	}
	return a.bridge.Dispatch(ctx, contract.Action{Kind: "pop"})
}

func (a *ConsoleAddon) setMode(ctx context.Context, mode string) error {
	if _, ok := a.bridge.Control.State().Current("flowview", false); !ok {
		return errors.New("Not viewing a flow.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	if !slices.Contains(a.modeOptions(ctx), strings.ToLower(mode)) {
		return errors.New("Invalid flowview mode.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	return a.bridge.Dispatch(ctx, contract.Action{Kind: "mode", Value: mode})
}

func (a *ConsoleAddon) modeOptions(context.Context) []string {
	return a.bridge.cfg.Registry.AvailableViews()
}

func (a *ConsoleAddon) mode(ctx context.Context) (string, error) {
	window, ok := a.bridge.Control.State().Current("flowview", false)
	if !ok {
		return "", errors.New("Not viewing a flow.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	f := a.bridge.cfg.View.Focus.Flow()
	if f == nil {
		return "", ErrEditConflict
	}
	result, err := a.bridge.cfg.Master.Call(ctx, "view.settings.getval", f, fmt.Sprintf("flowview_mode_%d", window.Index), a.bridge.cfg.Master.Options.Str("console_default_contentview"))
	if err != nil {
		return "", err
	}
	value, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("flowview mode returned %T, expected string", result)
	}
	return value, nil
}

func (a *ConsoleAddon) keyContexts(context.Context) []string { return keymap.Contexts() }

func (a *ConsoleAddon) bind(ctx context.Context, contexts []string, key string, cmd command.Cmd, args ...command.CmdArgs) error {
	binding := keymap.Binding{Key: key, Contexts: slices.Clone(contexts), Command: string(cmd) + " " + strings.Join(commandArguments(args), " ")}
	return a.bridge.Control.Apply(ctx, contract.Action{Kind: "edited"}, func(context.Context) error { return a.bridge.Keys.Add(binding) })
}

func (a *ConsoleAddon) unbind(ctx context.Context, contexts []string, key string) error {
	return a.bridge.Control.Apply(ctx, contract.Action{Kind: "edited"}, func(context.Context) error { return a.bridge.Keys.Remove(key, contexts) })
}

func (a *ConsoleAddon) focusedBinding() (contract.Binding, error) {
	window, ok := a.bridge.Control.State().Current("keybindings", true)
	if !ok {
		return contract.Binding{}, errors.New("Not viewing key bindings.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	if window.Binding == "" || window.Column == 1 {
		return contract.Binding{}, errors.New("No key binding focused") //nolint:staticcheck // Preserve upstream's command error text.
	}
	return a.bridge.binding(window.Binding)
}

func (a *ConsoleAddon) unbindFocus(ctx context.Context) error {
	binding, err := a.focusedBinding()
	if err != nil {
		return err
	}
	return a.unbind(ctx, binding.Contexts, binding.Key)
}

func (a *ConsoleAddon) executeBinding(ctx context.Context) error {
	binding, err := a.focusedBinding()
	if err != nil {
		return err
	}
	return a.commandPrompt(ctx, binding.Command)
}

func (a *ConsoleAddon) editBinding(ctx context.Context) error {
	binding, err := a.focusedBinding()
	if err != nil {
		return err
	}
	return a.commandPrompt(ctx, "console.key.bind", strings.Join(binding.Contexts, ","), binding.Key, binding.Command)
}
