// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package anticomp asks servers not to compress their responses.
package anticomp

import (
	"context"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

// AntiComp requests identity encoding when anticomp is enabled.
// Options are read only under addon dispatch.
type AntiComp struct{ options *options.Manager }

// New returns a compression-prevention addon using opts.
func New(opts *options.Manager) *AntiComp { return &AntiComp{options: opts} }

// Name returns the upstream addon name.
func (*AntiComp) Name() string { return "anticomp" }

// Load registers the upstream anticomp option.
func (*AntiComp) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "anticomp", options.TypeBool, false, "Try to convince servers to send us un-compressed data.")
}

// Request asks for identity encoding when the option is enabled.
func (a *AntiComp) Request(_ context.Context, f *flow.HTTPFlow) error {
	if a.options.Bool("anticomp") {
		f.Request.Anticomp()
	}
	return nil
}

var (
	_ addon.LoadHandler    = (*AntiComp)(nil)
	_ addon.RequestHandler = (*AntiComp)(nil)
)
