// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/external"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func (a *ConsoleAddon) registerEditing(loader *addon.Loader) error {
	for _, spec := range []struct {
		name, help string
		fn         any
		params     []string
		choice     string
	}{
		{"console.bodyview", "Spawn an external viewer for a flow request or response body based on the detected MIME type. We use the mailcap system to find the correct viewer, and fall back to the programs in $PAGER or $EDITOR if necessary.", a.bodyView, []string{"flow", "part"}, "console.bodyview.options"},
		{"console.bodyview.options", "Possible parts for console.bodyview.", a.bodyParts, nil, ""},
		{"console.edit.focus.options", "Possible components for console.edit.focus.", a.editParts, nil, ""},
		{"console.edit.focus", "Edit a component of the currently focused flow.", a.editFocus, []string{"flow_part"}, "console.edit.focus.options"},
	} {
		opts := []command.Option{command.WithHelp(spec.help), command.WithParams(spec.params...)}
		if spec.choice != "" {
			opts = append(opts, command.WithArgument(spec.params[len(spec.params)-1], command.Choice(spec.choice)))
		}
		if err := loader.AddCommand(spec.name, spec.fn, opts...); err != nil {
			return err
		}
	}
	for _, spec := range []struct{ operation, help string }{
		{"add", "Add a row after the cursor."},
		{"insert", "Insert a row before the cursor."},
		{"delete", "Delete row"},
		{"editor", "Spawn an external editor on the current cell."},
	} {
		if err := loader.AddCommand("console.grideditor."+spec.operation, func(ctx context.Context) error {
			return a.bridge.Dispatch(ctx, contract.Action{Kind: "grid", Value: spec.operation})
		}, command.WithHelp(spec.help)); err != nil {
			return err
		}
	}
	for _, spec := range []struct{ operation, help string }{
		{"load", "Read a file into the current cell."},
		{"load_escaped", "Read a file containing a Python-style escaped string into the current cell."},
		{"save", "Save data to file as a CSV."},
	} {
		if err := loader.AddCommand("console.grideditor."+spec.operation, func(ctx context.Context, path command.Path) error {
			return a.bridge.Dispatch(ctx, contract.Action{Kind: "grid", Value: spec.operation, Text: string(path)})
		}, command.WithHelp(spec.help), command.WithParams("path")); err != nil {
			return err
		}
	}
	return nil
}

func (a *ConsoleAddon) bodyParts(context.Context) []string { return []string{"request", "response"} }

func (a *ConsoleAddon) bodyView(ctx context.Context, f flow.Flow, part string) error {
	h, ok := f.(*flow.HTTPFlow)
	if !ok || h == nil || part != "request" && part != "response" || part == "request" && h.Request == nil || part == "response" && h.Response == nil {
		return fmt.Errorf("Part must be either request or response, not %s.", part) //nolint:staticcheck // Preserve upstream's command error text.
	}
	data, _, err := messageContent(f, part+"-body", -1)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("No content to view.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	session, err := a.captureEdit(f, part+"-body")
	if err != nil {
		return err
	}
	return a.bridge.Dispatch(ctx, contract.Action{Kind: "external", Value: "view", Text: part + "-body", Target: &session.Target})
}

func (a *ConsoleAddon) captureEdit(f flow.Flow, part string) (*external.EditSession, error) {
	if f == nil {
		return nil, errors.New("No flow selected.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	session, err := external.Capture(f, part, a.detailOptions())
	if err == nil {
		session.Flow.Common().Live = f.Common().Live
	}
	return session, err
}

func (a *ConsoleAddon) detailOptions() contract.DetailOptions {
	opts := a.bridge.cfg.Master.Options
	detail := contract.DetailOptions{Registry: a.bridge.cfg.Registry, DefaultContentView: opts.Str("console_default_contentview")}
	if opts.Has("content_view_lines_cutoff") {
		detail.LineCutoff = opts.Int("content_view_lines_cutoff")
	}
	if opts.Has("protobuf_definitions") {
		if definitions := opts.OptStr("protobuf_definitions"); definitions != nil {
			detail.ProtobufDefinitions = *definitions
		}
	}
	return detail
}

func (a *ConsoleAddon) editParts(ctx context.Context) ([]string, error) {
	f := a.bridge.cfg.View.Focus.Flow()
	if f == nil {
		return nil, errors.New("No flow selected.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	mode, err := a.mode(ctx)
	if err != nil {
		mode = "auto"
	}
	var parts []string
	addInteractive := func(part string, index int) error {
		data, metadata, err := messageContent(f, part, index)
		if err != nil {
			return err
		}
		metadata.ProtobufDefinitions = a.detailOptions().ProtobufDefinitions
		view, err := a.bridge.cfg.Registry.GetView(data, metadata, mode)
		if err != nil {
			return err
		}
		if _, ok := view.(contentviews.InteractiveView); ok {
			parts = append(parts, part+" ("+view.Name()+")")
		}
		return nil
	}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		parts = append(parts, "cookies", "urlencoded form", "multipart form", "path", "method", "query", "reason", "request-headers", "response-headers", "request-body", "response-body", "status_code", "set-cookies", "url")
		if f.Request != nil {
			if err := addInteractive("request-body", -1); err != nil {
				return nil, err
			}
		}
		if f.Response != nil {
			if err := addInteractive("response-body", -1); err != nil {
				return nil, err
			}
		}
		if f.WebSocket != nil && len(f.WebSocket.Messages) != 0 {
			if err := addInteractive("websocket-message", len(f.WebSocket.Messages)-1); err != nil {
				return nil, err
			}
		}
	case *flow.TCPFlow:
		parts = append(parts, "tcp-message")
		if len(f.Messages) != 0 {
			if err := addInteractive("tcp-message", len(f.Messages)-1); err != nil {
				return nil, err
			}
		}
	case *flow.UDPFlow:
		parts = append(parts, "udp-message")
		if len(f.Messages) != 0 {
			if err := addInteractive("udp-message", len(f.Messages)-1); err != nil {
				return nil, err
			}
		}
	case *flow.DNSFlow:
		return nil, errors.New("Cannot edit DNS flows yet, please submit a patch.") //nolint:staticcheck // Preserve upstream's unsupported-flow diagnostic.
	default:
		return nil, fmt.Errorf("unsupported flow type %T", f)
	}
	return append(parts, "comment"), nil
}

func (a *ConsoleAddon) editFocus(ctx context.Context, part string) error {
	f := a.bridge.cfg.View.Focus.Flow()
	if f == nil {
		return errors.New("No flow selected.") //nolint:staticcheck // Preserve upstream's command error text.
	}
	if part == "method" || part == "status_code" || part == "reason" {
		return a.commandPrompt(ctx, "flow.set", "@focus", part)
	}
	session, err := a.captureEdit(f, part)
	if err != nil {
		return err
	}
	if session.Mode != "" {
		view, ok := a.bridge.cfg.Registry.Get(session.Mode)
		if _, interactive := view.(contentviews.InteractiveView); !ok || !interactive {
			return fmt.Errorf("Contentview %s is not bidirectional.", session.Mode) //nolint:staticcheck // Preserve upstream's command error text.
		}
	}
	if session.Mode != "" || strings.HasSuffix(part, "-body") || strings.HasSuffix(part, "-message") || part == "url" {
		return a.bridge.Dispatch(ctx, contract.Action{Kind: "external", Value: "edit", Text: part, Target: &session.Target})
	}
	request := &contract.GridRequest{Flow: session.Flow, Target: session.Target, Mode: session.Mode, Detail: session.Options}
	return a.bridge.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "edit_" + session.Target.Part, Context: "grideditor", FlowID: session.Target.FlowID, Editor: session.Target.Part}, Text: part, Target: &session.Target, Grid: request})
}

func messageContent(f flow.Flow, part string, index int) ([]byte, contentviews.Metadata, error) {
	metadata := contentviews.Metadata{Flow: f}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		switch part {
		case "request-body":
			if f.Request != nil {
				metadata.HTTPMessage, metadata.HTTPRequest = &f.Request.Message, f.Request
			}
		case "response-body":
			if f.Response != nil {
				metadata.HTTPMessage = &f.Response.Message
			}
		case "websocket-message":
			if f.WebSocket != nil && index >= 0 && index < len(f.WebSocket.Messages) {
				metadata.WebSocketMessage, metadata.Protocol = f.WebSocket.Messages[index], "websocket"
				return metadata.WebSocketMessage.Content, metadata, nil
			}
		}
		if metadata.HTTPMessage != nil {
			metadata.Protocol = "http"
			metadata.ContentType, _, _ = strings.Cut(metadata.HTTPMessage.Headers.Get("content-type"), ";")
			metadata.ContentType = strings.TrimSpace(metadata.ContentType)
			return metadata.HTTPMessage.ContentOrRaw(), metadata, nil
		}
	case *flow.TCPFlow:
		if index >= 0 && index < len(f.Messages) {
			metadata.TCPMessage, metadata.Protocol = f.Messages[index], "tcp"
			return metadata.TCPMessage.Content, metadata, nil
		}
	case *flow.UDPFlow:
		if index >= 0 && index < len(f.Messages) {
			metadata.UDPMessage, metadata.Protocol = f.Messages[index], "udp"
			return metadata.UDPMessage.Content, metadata, nil
		}
	}
	return nil, metadata, errors.New("message missing")
}
