// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package modifyheaders rewrites request and response headers using flow filters.
package modifyheaders

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/filter/regex"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/spec"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/options"
)

const maxReplacementBytes = 16 << 20

// ModifySpec is a filtered header name or body pattern and its replacement.
// State belongs to the addon dispatch domain; callers must not mutate a spec
// while an addon is using it.
type ModifySpec struct {
	// Matches selects the flows to modify.
	Matches filter.Expr
	// Subject holds the decoded header name or bytes regular expression.
	Subject []byte
	// ReplacementStr is escaped text or an @-prefixed file path.
	ReplacementStr string
}

// ReadReplacement decodes the replacement text or reads its @-prefixed file.
// File paths expand ~ and ~user. Files are read on every call, bounded to 16 MiB;
// larger files, invalid escapes, and unreadable files return an error.
func (s ModifySpec) ReadReplacement() ([]byte, error) {
	path, file := strings.CutPrefix(s.ReplacementStr, "@")
	if !file {
		return strutil.EscapedStrToBytes(s.ReplacementStr)
	}
	if strings.HasPrefix(path, "~") {
		owner, suffix, _ := strings.Cut(path[1:], "/")
		home := ""
		if owner == "" {
			home, _ = os.UserHomeDir()
		} else if account, err := user.Lookup(owner); err == nil {
			home = account.HomeDir
		}
		if home != "" {
			path = filepath.Join(home, suffix)
		}
	}
	f, err := os.Open(path) // #nosec G304 -- The option intentionally selects the replacement file; reads are bounded.
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxReplacementBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > maxReplacementBytes {
		return nil, fmt.Errorf("replacement file exceeds %d bytes", maxReplacementBytes)
	}
	return data, nil
}

// ParseModifySpec parses a filtered modification with Python byte escapes.
// When subjectIsRegex is true it validates the subject with filter/regex's
// Python syntax and bounded fallback engine. It validates the replacement
// immediately, including the 16 MiB limit on @-prefixed files.
func ParseModifySpec(option string, subjectIsRegex bool) (ModifySpec, error) {
	matches, subjectStr, replacement, err := spec.Parse(option)
	if err != nil {
		return ModifySpec{}, err
	}
	subject, err := strutil.EscapedStrToBytes(subjectStr)
	if err != nil {
		return ModifySpec{}, err
	}
	if subjectIsRegex {
		if _, err := regex.Compile(string(subject), 0); err != nil {
			return ModifySpec{}, fmt.Errorf("Invalid regular expression %s (%w)", pyrepr.Bytes(subject), err) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
	}
	s := ModifySpec{Matches: matches, Subject: subject, ReplacementStr: replacement}
	if _, err := s.ReadReplacement(); err != nil {
		if path, file := strings.CutPrefix(replacement, "@"); file {
			return ModifySpec{}, fmt.Errorf("Invalid file path: %s (%w)", path, err) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
		return ModifySpec{}, err
	}
	return s, nil
}

// ModifyHeaders removes and appends headers selected by modification patterns.
type ModifyHeaders struct {
	options      *options.Manager
	replacements []ModifySpec
}

// New returns a header modifier using opts.
func New(opts *options.Manager) *ModifyHeaders { return &ModifyHeaders{options: opts} }

// Name returns the upstream addon name.
func (*ModifyHeaders) Name() string { return "modifyheaders" }

// Load registers the upstream modify_headers option.
func (*ModifyHeaders) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "modify_headers", options.TypeSeq, []string{}, `Header modify pattern of the form "[/flow-filter]/header-name/[@]header-value", where the separator can be any character. The @ allows to provide a file path that is used to read the header value string. An empty header-value removes existing header-name headers.`)
}

// Configure validates replacements when modify_headers changes.
func (m *ModifyHeaders) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["modify_headers"]; !ok {
		return nil
	}
	m.replacements = nil
	for _, option := range m.options.Seq("modify_headers") {
		replacement, err := ParseModifySpec(option, false)
		if err != nil {
			return options.Errorf("Cannot parse modify_headers option %s: %v", option, err)
		}
		m.replacements = append(m.replacements, replacement)
	}
	return nil
}

// RequestHeaders rewrites live requests not already answered or failed.
func (m *ModifyHeaders) RequestHeaders(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Response != nil || f.Error != nil || !f.Live {
		return nil
	}
	m.run(ctx, f, &f.Request.Headers)
	return nil
}

// ResponseHeaders rewrites live responses not already failed.
func (m *ModifyHeaders) ResponseHeaders(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Error != nil || !f.Live {
		return nil
	}
	m.run(ctx, f, &f.Response.Headers)
	return nil
}

func (m *ModifyHeaders) run(ctx context.Context, f *flow.HTTPFlow, headers *httpmsg.Headers) {
	matches := make([]bool, len(m.replacements))
	for i, s := range m.replacements {
		matches[i] = filter.Match(s.Matches, f)
	}
	for i, s := range m.replacements {
		if matches[i] {
			headers.Del(string(s.Subject))
		}
	}
	for i, s := range m.replacements {
		if !matches[i] {
			continue
		}
		replacement, err := s.ReadReplacement()
		if err != nil {
			slog.WarnContext(ctx, fmt.Sprintf("Could not read replacement file: %v", err))
			continue
		}
		if len(replacement) != 0 {
			headers.Add(string(s.Subject), string(replacement))
		}
	}
}

var (
	_ addon.LoadHandler            = (*ModifyHeaders)(nil)
	_ addon.ConfigureHandler       = (*ModifyHeaders)(nil)
	_ addon.RequestHeadersHandler  = (*ModifyHeaders)(nil)
	_ addon.ResponseHeadersHandler = (*ModifyHeaders)(nil)
)
