// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package mapremote rewrites the URLs of matching live HTTP requests.
package mapremote

import (
	"context"
	"fmt"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/filter/regex"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/spec"
	"github.com/zchee/mitmproxy-go/options"
)

type replacement struct {
	matches filter.Expr
	pattern *regex.Pattern
	value   string
}

// MapRemote rewrites requests in option order using Python regex templates.
// Patterns are bounded to 1 MiB and transformed URLs to 256 MiB by filter/regex.
// Shared state is accessed only during addon dispatch.
type MapRemote struct {
	options      *options.Manager
	replacements []replacement
}

// New returns a remote URL mapper using opts.
func New(opts *options.Manager) *MapRemote { return &MapRemote{options: opts} }

// Name returns the upstream addon name.
func (*MapRemote) Name() string { return "mapremote" }

// Load registers the upstream map_remote option.
func (*MapRemote) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "map_remote", options.TypeSeq, []string{}, `Map remote resources to another remote URL using a pattern of the form "[/flow-filter]/url-regex/replacement", where the separator can be any character.`)
}

// Configure parses the replacement rules when map_remote changes.
func (m *MapRemote) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, changed := updated["map_remote"]; !changed {
		return nil
	}
	m.replacements = nil
	for _, option := range m.options.Seq("map_remote") {
		r, err := parse(option)
		if err != nil {
			return options.Errorf("Cannot parse map_remote option %s: %v", option, err)
		}
		m.replacements = append(m.replacements, r)
	}
	return nil
}

func parse(option string) (replacement, error) {
	matches, subject, value, err := spec.Parse(option)
	if err != nil {
		return replacement{}, err
	}
	pattern, err := regex.CompilePattern(subject, regex.Unicode)
	if err != nil {
		return replacement{}, fmt.Errorf("Invalid regular expression %s (%v)", pyrepr.Str(subject), err) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
	return replacement{matches: matches, pattern: pattern, value: value}, nil
}

// Request rewrites matching requests unless already answered, failed or inactive.
// An unchanged pretty URL must not update the target or its Host header.
func (m *MapRemote) Request(_ context.Context, f *flow.HTTPFlow) error {
	if f.Response != nil || f.Error != nil || !f.Live {
		return nil
	}
	for _, r := range m.replacements {
		if !filter.Match(r.matches, f) {
			continue
		}
		url := f.Request.PrettyURL()
		rewritten, err := r.pattern.SubString(r.value, url, 0)
		if err != nil {
			return fmt.Errorf("mapremote: cannot replace URL: %w", err)
		}
		if url != rewritten {
			if err := f.Request.SetURL(rewritten); err != nil {
				return err
			}
		}
	}
	return nil
}

var (
	_ addon.LoadHandler      = (*MapRemote)(nil)
	_ addon.ConfigureHandler = (*MapRemote)(nil)
	_ addon.RequestHandler   = (*MapRemote)(nil)
)
