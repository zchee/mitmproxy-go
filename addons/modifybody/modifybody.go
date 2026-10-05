// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package modifybody rewrites buffered request and response bodies using flow filters.
package modifybody

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/modifyheaders"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/filter/regex"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/options"
)

type replacement struct {
	spec    modifyheaders.ModifySpec
	pattern *regex.Pattern
}

// ModifyBody applies ordered replacements to the decoded bodies of live flows.
// Replacement files are reread for every matching flow, bounded to 16 MiB by
// modifyheaders.ModifySpec. Patterns are bounded to 1 MiB; transformed bodies
// are bounded to 256 MiB by filter/regex. State belongs to addon dispatch.
type ModifyBody struct {
	options      *options.Manager
	replacements []replacement
}

// New returns a body modifier using opts.
func New(opts *options.Manager) *ModifyBody { return &ModifyBody{options: opts} }

// Name returns the upstream addon name.
func (*ModifyBody) Name() string { return "modifybody" }

// Load registers the upstream modify_body option.
func (*ModifyBody) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "modify_body", options.TypeSeq, []string{}, `Replacement pattern of the form "[/flow-filter]/regex/[@]replacement", where the separator can be any character. The @ allows to provide a file path that is used to read the replacement string.`)
}

// Configure validates replacement specifications and reports streaming conflicts.
func (m *ModifyBody) Configure(ctx context.Context, updated map[string]struct{}) error {
	_, bodyChanged := updated["modify_body"]
	if bodyChanged {
		m.replacements = nil
		for _, option := range m.options.Seq("modify_body") {
			s, err := modifyheaders.ParseModifySpec(option, true)
			if err != nil {
				return options.Errorf("Cannot parse modify_body option %s: %v", option, err)
			}
			p, err := regex.CompilePattern(string(s.Subject), regex.DotAll)
			if err != nil {
				return options.Errorf("Cannot parse modify_body option %s: Invalid regular expression %s (%v)", option, pyrepr.Bytes(s.Subject), err)
			}
			m.replacements = append(m.replacements, replacement{spec: s, pattern: p})
		}
	}
	_, streamingChanged := updated["stream_large_bodies"]
	if len(m.replacements) > 0 && (bodyChanged || streamingChanged) {
		if _, exists := m.options.Lookup("stream_large_bodies"); exists {
			if threshold := m.options.OptStr("stream_large_bodies"); threshold != nil && *threshold != "" {
				slog.Log(ctx, addon.LevelAlert, "Both modify_body and stream_large_bodies are active. Streamed bodies will not be modified.")
			}
		}
	}
	return nil
}

// Request rewrites live requests not already answered or failed.
func (m *ModifyBody) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Response != nil || f.Error != nil || !f.Live {
		return nil
	}
	return m.run(ctx, f, &f.Request.Message)
}

// Response rewrites live responses not already failed.
func (m *ModifyBody) Response(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Error != nil || !f.Live {
		return nil
	}
	return m.run(ctx, f, &f.Response.Message)
}

func (m *ModifyBody) run(ctx context.Context, f *flow.HTTPFlow, message *httpmsg.Message) error {
	if message.RawContent == nil {
		return nil
	}
	for _, r := range m.replacements {
		if !filter.Match(r.spec.Matches, f) {
			continue
		}
		data, err := r.spec.ReadReplacement()
		if err != nil {
			slog.WarnContext(ctx, fmt.Sprintf("Could not read replacement file: %v", err))
			continue
		}
		content, err := message.Content()
		if err != nil {
			return fmt.Errorf("modifybody: cannot decode body: %w", err)
		}
		// Upstream's replacement callback returns literal bytes, not a template.
		// Escape backslashes so Python group and character escapes stay literal.
		literal := bytes.ReplaceAll(data, []byte{'\\'}, []byte{'\\', '\\'})
		content, err = r.pattern.Sub(literal, content, 0)
		if err != nil {
			return fmt.Errorf("modifybody: cannot replace body: %w", err)
		}
		message.SetContent(content)
	}
	return nil
}

var (
	_ addon.LoadHandler      = (*ModifyBody)(nil)
	_ addon.ConfigureHandler = (*ModifyBody)(nil)
	_ addon.RequestHandler   = (*ModifyBody)(nil)
	_ addon.ResponseHandler  = (*ModifyBody)(nil)
)
