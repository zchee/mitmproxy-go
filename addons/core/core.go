// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package core registers commands for editing flows and managing options.
package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/emoji"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/options"
)

// Core provides the built-in flow and option commands. Its command functions
// are called through the manager, under its synchronous dispatch hold.
type Core struct {
	manager *addon.Manager
}

// New returns the core addon for manager, which supplies its options, commands
// and update hooks. Register the returned addon with that same manager.
func New(manager *addon.Manager) *Core { return &Core{manager: manager} }

// defaultDecodeLimit is the default of the content_decode_limit option. It
// parses to httpmsg's own default bound, which Done restores.
const defaultDecodeLimit = "256m"

// Load registers core's commands and the Go-only decoded-body limit option.
func (c *Core) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "content_decode_limit", options.TypeStr, defaultDecodeLimit, "Maximum size of a decoded HTTP body. Bodies exceeding this limit are treated as undecodable."); err != nil {
		return err
	}
	commands := []struct {
		name   string
		fn     any
		help   string
		params []string
		choice string
	}{
		{"set", c.set, "Set an option. When the value is omitted, booleans are set to true, strings and integers are set to None (if permitted), and sequences are emptied. Boolean values can be true, false or toggle. Multiple values are concatenated with a single space.", []string{"option", "value"}, ""},
		{"flow.resume", c.resume, "Resume flows if they are intercepted.", []string{"flows"}, ""},
		{"flow.mark", c.mark, "Mark flows.", []string{"flows", "marker"}, ""},
		{"flow.mark.toggle", c.markToggle, "Toggle mark for flows.", []string{"flows"}, ""},
		{"flow.kill", c.kill, "Kill running flows.", []string{"flows"}, ""},
		{"flow.revert", c.revert, "Revert flow changes.", []string{"flows"}, ""},
		{"flow.set.options", c.flowSetOptions, "", nil, ""},
		{"flow.set", c.flowSet, "Quickly set a number of common values on flows.", []string{"flows", "attr", "value"}, "attr"},
		{"flow.decode", c.decode, "Decode flows.", []string{"flows", "part"}, ""},
		{"flow.encode.toggle", c.encodeToggle, "Toggle flow encoding on and off, using deflate for encoding.", []string{"flows", "part"}, ""},
		{"flow.encode", c.encode, "Encode flows with a specified encoding.", []string{"flows", "part", "encoding"}, "encoding"},
		{"flow.encode.options", c.encodeOptions, "The possible values for an encoding specification.", nil, ""},
		{"options.load", c.optionsLoad, "Load options from a file.", []string{"path"}, ""},
		{"options.save", c.optionsSave, "Save options to a file.", []string{"path"}, ""},
		{"options.reset", c.optionsReset, "Reset all options to defaults.", nil, ""},
		{"options.reset.one", c.optionsResetOne, "Reset one option to its default value.", []string{"name"}, ""},
	}
	for _, cmd := range commands {
		opts := []command.Option{command.WithHelp(cmd.help), command.WithParams(cmd.params...)}
		if cmd.choice != "" {
			opts = append(opts, command.WithArgument(cmd.choice, command.Choice(cmd.name+".options")))
		}
		if err := loader.AddCommand(cmd.name, cmd.fn, opts...); err != nil {
			return err
		}
	}
	return nil
}

// Configure validates certificate options and publishes the decoded-body limit.
// The bound is process-global; the last configure wins. A zero limit permits only
// empty decoded bodies, not unlimited decoding.
func (c *Core) Configure(ctx context.Context, updated map[string]struct{}) error {
	opts := c.manager.Options()
	if opts.Bool("add_upstream_certs_to_client_chain") && !opts.Bool("upstream_cert") {
		return options.Errorf("add_upstream_certs_to_client_chain requires the upstream_cert option to be enabled.")
	}
	if _, ok := updated["client_certs"]; ok {
		if path := opts.OptStr("client_certs"); path != nil && *path != "" {
			expanded, err := command.PathType.Parse(ctx, c.manager.Commands(), *path)
			if err != nil {
				return &options.OptionsError{Msg: "Invalid client certificate path: " + *path, Err: err}
			}
			if _, err := os.Stat(string(expanded.(command.Path))); err != nil {
				return options.Errorf("Client certificate path does not exist: %s", *path)
			}
		}
	}
	if _, ok := updated["content_decode_limit"]; ok {
		value := opts.Str("content_decode_limit")
		limit, err := human.ParseSize(value)
		if err != nil || limit < 0 {
			return &options.OptionsError{Msg: fmt.Sprintf("Invalid content_decode_limit: %s", value), Err: err}
		}
		// The decode paths are package-level code shared by every manager in
		// the process, so the limit is process-global: the last configure wins.
		httpmsg.SetDecodeLimit(limit)
	}
	return nil
}

// Done restores the default decoded-body limit when the addon is removed.
func (*Core) Done(context.Context) error {
	limit, err := human.ParseSize(defaultDecodeLimit)
	if err != nil {
		return err
	}
	httpmsg.SetDecodeLimit(limit)
	return nil
}

func (c *Core) set(ctx context.Context, option string, value ...string) error {
	specs := []string{option}
	if len(value) != 0 {
		specs = make([]string, len(value))
		for i, v := range value {
			specs[i] = option + "=" + v
		}
	}
	if err := c.manager.Options().Set(ctx, specs...); err != nil {
		if _, ok := errors.AsType[*options.OptionsError](err); ok {
			return &command.Error{Err: err}
		}
		return err
	}
	return nil
}

func (c *Core) resume(ctx context.Context, flows []flow.Flow) error {
	updated := make([]flow.Flow, 0, len(flows))
	for _, f := range flows {
		if f.Common().Intercepted() {
			updated = append(updated, f)
		}
	}
	for _, f := range updated {
		f.Common().Resume()
	}
	return c.manager.Trigger(ctx, addon.UpdateHook{Flows: updated})
}

func (c *Core) mark(ctx context.Context, flows []flow.Flow, marker command.Marker) error {
	if _, ok := emoji.Char(string(marker)); marker != "" && !ok {
		return &command.Error{Msg: "invalid marker value"}
	}
	updated := make([]flow.Flow, 0, len(flows))
	for _, f := range flows {
		f.Common().Marked = string(marker)
		updated = append(updated, f)
	}
	return c.manager.Trigger(ctx, addon.UpdateHook{Flows: updated})
}

func (c *Core) markToggle(ctx context.Context, flows []flow.Flow) error {
	for _, f := range flows {
		if f.Common().Marked != "" {
			f.Common().Marked = ""
		} else {
			f.Common().Marked = ":default:"
		}
	}
	return c.manager.Trigger(ctx, addon.UpdateHook{Flows: flows})
}

func (c *Core) kill(ctx context.Context, flows []flow.Flow) error {
	updated := make([]flow.Flow, 0, len(flows))
	for _, f := range flows {
		if f.Common().Killable() {
			if err := f.Common().Kill(); err != nil {
				return err
			}
			updated = append(updated, f)
		}
	}
	slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Killed %d flows.", len(updated)))
	return c.manager.Trigger(ctx, addon.UpdateHook{Flows: updated})
}

func (c *Core) revert(ctx context.Context, flows []flow.Flow) error {
	updated := make([]flow.Flow, 0, len(flows))
	for _, f := range flows {
		if f.Modified() {
			if err := f.Revert(); err != nil {
				return err
			}
			updated = append(updated, f)
		}
	}
	slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Reverted %d flows.", len(updated)))
	return c.manager.Trigger(ctx, addon.UpdateHook{Flows: updated})
}

func (*Core) flowSetOptions(context.Context) []string {
	return []string{"host", "status_code", "method", "path", "url", "reason"}
}

func (c *Core) flowSet(ctx context.Context, flows []flow.Flow, attr, value string) error {
	var status int
	if attr == "status_code" {
		n, err := command.IntType.Parse(ctx, c.manager.Commands(), value)
		if err != nil {
			return &command.Error{Msg: "Status code is not an integer: " + value, Err: err}
		}
		status = n.(int)
	}
	for _, f := range flows {
		h, ok := f.(*flow.HTTPFlow)
		if !ok {
			continue
		}
		if req := h.Request; req != nil {
			switch attr {
			case "method":
				req.Method = value
			case "host":
				req.SetHost(value)
			case "path":
				req.Path = value
			case "url":
				if err := req.SetURL(value); err != nil {
					return &command.Error{Msg: fmt.Sprintf("URL %s is invalid: %v", pyrepr.Str(value), err), Err: err}
				}
			}
		}
		if resp := h.Response; resp != nil {
			switch attr {
			case "status_code":
				resp.StatusCode = status
				if reason := httpmsg.StatusText(status); reason != "" {
					resp.Reason = reason
				}
			case "reason":
				resp.Reason = value
			}
		}
	}
	// Upstream leaves its local request-update flag true even for attributes
	// that do not apply, so the update hook includes every supplied flow.
	if err := c.manager.Trigger(ctx, addon.UpdateHook{Flows: flows}); err != nil {
		return err
	}
	slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Set %s on  %d flows.", attr, len(flows)))
	return nil
}

func messagePart(f flow.Flow, part string) *httpmsg.Message {
	if h, ok := f.(*flow.HTTPFlow); ok {
		switch part {
		case "request":
			if h.Request != nil {
				return &h.Request.Message
			}
		case "response":
			if h.Response != nil {
				return &h.Response.Message
			}
		}
	}
	return nil
}

func (c *Core) decode(ctx context.Context, flows []flow.Flow, part string) error {
	updated := make([]flow.Flow, 0, len(flows))
	for _, f := range flows {
		if p := messagePart(f, part); p != nil {
			f.Backup()
			if err := p.Decode(true); err != nil {
				return err
			}
			updated = append(updated, f)
		}
	}
	if err := c.manager.Trigger(ctx, addon.UpdateHook{Flows: updated}); err != nil {
		return err
	}
	slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Decoded %d flows.", len(updated)))
	return nil
}

func (c *Core) encodeToggle(ctx context.Context, flows []flow.Flow, part string) error {
	updated := make([]flow.Flow, 0, len(flows))
	for _, f := range flows {
		if p := messagePart(f, part); p != nil {
			f.Backup()
			encoding, ok := p.Headers.Lookup("content-encoding")
			var err error
			if !ok || encoding == "identity" {
				err = p.Encode("deflate")
			} else {
				err = p.Decode(true)
			}
			if err != nil {
				return err
			}
			updated = append(updated, f)
		}
	}
	if err := c.manager.Trigger(ctx, addon.UpdateHook{Flows: updated}); err != nil {
		return err
	}
	slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Toggled encoding on %d flows.", len(updated)))
	return nil
}

func (c *Core) encode(ctx context.Context, flows []flow.Flow, part, encoding string) error {
	updated := make([]flow.Flow, 0, len(flows))
	for _, f := range flows {
		if p := messagePart(f, part); p != nil {
			current, ok := p.Headers.Lookup("content-encoding")
			if !ok || current == "identity" {
				f.Backup()
				if err := p.Encode(encoding); err != nil {
					return err
				}
				updated = append(updated, f)
			}
		}
	}
	if err := c.manager.Trigger(ctx, addon.UpdateHook{Flows: updated}); err != nil {
		return err
	}
	slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Encoded %d flows.", len(updated)))
	return nil
}

func (*Core) encodeOptions(context.Context) []string {
	return []string{"gzip", "deflate", "br", "zstd"}
}

func (c *Core) optionsLoad(ctx context.Context, path command.Path) error {
	if err := c.manager.Options().LoadPaths(ctx, string(path)); err != nil {
		return &command.Error{Msg: "Could not load options - " + err.Error(), Err: err}
	}
	return nil
}

func (c *Core) optionsSave(_ context.Context, path command.Path) error {
	if err := c.manager.Options().Save(string(path), false); err != nil {
		if _, ok := errors.AsType[*options.OptionsError](err); ok {
			return err
		}
		return &command.Error{Msg: "Could not save options - " + err.Error(), Err: err}
	}
	return nil
}

func (c *Core) optionsReset(ctx context.Context) error {
	return c.manager.Options().Reset(ctx)
}

func (c *Core) optionsResetOne(ctx context.Context, name string) error {
	opts := c.manager.Options()
	if !opts.Has(name) {
		return &command.Error{Msg: "No such option: " + name}
	}
	return opts.Update(ctx, map[string]any{name: opts.Default(name)})
}
