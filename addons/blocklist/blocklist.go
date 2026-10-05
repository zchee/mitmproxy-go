// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package blocklist blocks matching requests with empty responses or a closed connection.
package blocklist

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/spec"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/options"
)

type rule struct {
	matches filter.Expr
	status  int
}

// BlockList applies block_list rules in option order under addon dispatch.
// HTTP status integers must fit the platform's int type.
type BlockList struct {
	options *options.Manager
	items   []rule
}

// New returns a request blocker using opts.
func New(opts *options.Manager) *BlockList { return &BlockList{options: opts} }

// Name returns the upstream addon name.
func (*BlockList) Name() string { return "blocklist" }

// Load registers the upstream block_list option.
func (*BlockList) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "block_list", options.TypeSeq, []string{}, `Block matching requests and return an empty response with the specified HTTP status. Option syntax is "/flow-filter/status-code", where flow-filter describes which requests this rule should be applied to and status-code is the HTTP status code to return for blocked requests. The separator ("/" in the example) can be any character. Setting a non-standard status code of 444 will close the connection without sending a response.`)
}

// Configure parses rules when block_list changes.
func (b *BlockList) Configure(ctx context.Context, updated map[string]struct{}) error {
	if _, changed := updated["block_list"]; !changed {
		return nil
	}
	b.items = nil
	for _, option := range b.options.Seq("block_list") {
		r, err := parse(ctx, option)
		if err != nil {
			return options.Errorf("Cannot parse block_list option %s: %v", option, err)
		}
		b.items = append(b.items, r)
	}
	return nil
}

func parse(_ context.Context, option string) (rule, error) {
	_, size := utf8.DecodeRuneInString(option)
	if option == "" || len(strings.SplitN(option[size:], option[:size], 3)) != 2 {
		return rule{}, errors.New("Invalid number of parameters (2 are expected)") //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
	_, pattern, status, err := spec.Parse(option)
	if err != nil {
		return rule{}, err
	}
	// ParseSize already implements Python's integer grammar; disallow its size suffixes.
	last, _ := utf8.DecodeLastRuneInString(strings.TrimSpace(status))
	number, err := human.ParseSize(status)
	if err != nil || !unicode.IsDigit(last) || int64(int(number)) != number {
		return rule{}, fmt.Errorf("Invalid HTTP status code: %s", status) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
	matches, err := filter.Parse(pattern)
	if err != nil {
		return rule{}, err
	}
	return rule{matches: matches, status: int(number)}, nil
}

// Request blocks matching live requests unless already answered or failed.
// The special status 444 kills the flow without constructing a response.
func (b *BlockList) Request(_ context.Context, f *flow.HTTPFlow) error {
	if f.Response != nil || f.Error != nil || !f.Live {
		return nil
	}
	for _, r := range b.items {
		if !filter.Match(r.matches, f) {
			continue
		}
		if f.Metadata == nil {
			f.Metadata = state.NewMap(1)
		}
		f.Metadata.Set("blocklisted", true)
		if r.status == httpmsg.StatusNoResponse {
			if err := f.Kill(); err != nil {
				return err
			}
		} else {
			headers := httpmsg.Headers{}
			headers.Set("Server", version.String())
			response, err := httpmsg.MakeResponse(r.status, []byte{}, headers)
			if err != nil {
				return err
			}
			f.Response = response
		}
	}
	return nil
}

var (
	_ addon.LoadHandler      = (*BlockList)(nil)
	_ addon.ConfigureHandler = (*BlockList)(nil)
	_ addon.RequestHandler   = (*BlockList)(nil)
)
