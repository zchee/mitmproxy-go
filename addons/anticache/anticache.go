// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package anticache removes request headers that permit a not-modified response.
package anticache

import (
	"context"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

// AntiCache strips conditional cache headers when anticache is enabled.
// Options are read only under addon dispatch.
type AntiCache struct{ options *options.Manager }

// New returns a cache-prevention addon using opts.
func New(opts *options.Manager) *AntiCache { return &AntiCache{options: opts} }

// Name returns the upstream addon name.
func (*AntiCache) Name() string { return "anticache" }

// Load registers the upstream anticache option.
func (*AntiCache) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "anticache", options.TypeBool, false, "Strip out request headers that might cause the server to return 304-not-modified.")
}

// Request removes cache validators when the option is enabled.
func (a *AntiCache) Request(_ context.Context, f *flow.HTTPFlow) error {
	if a.options.Bool("anticache") {
		f.Request.Anticache()
	}
	return nil
}

var (
	_ addon.LoadHandler    = (*AntiCache)(nil)
	_ addon.RequestHandler = (*AntiCache)(nil)
)
