// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package intercept pauses flows matching the configured interception filter.
// All addon state is accessed under the addon dispatch lock.
package intercept

import (
	"context"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/options"
)

// Intercept pauses matching non-replayed flows until they are resumed or killed.
// Construct it with New using the manager's option registry.
type Intercept struct {
	options *options.Manager
	filt    filter.Expr
}

// New constructs an interception addon using opts.
func New(opts *options.Manager) *Intercept { return &Intercept{options: opts} }

// Load registers intercept_active and intercept with upstream's defaults.
func (i *Intercept) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "intercept_active", options.TypeBool, false, "Intercept toggle"); err != nil {
		return err
	}
	return loader.AddOption(ctx, "intercept", options.TypeOptStr, (*string)(nil), "Intercept filter expression.")
}

// Configure compiles a changed filter and activates or deactivates interception.
// A malformed filter returns an OptionsError without replacing the previous one.
func (i *Intercept) Configure(ctx context.Context, updated map[string]struct{}) error {
	if _, ok := updated["intercept"]; !ok {
		return nil
	}
	var expression filter.Expr
	value := i.options.OptStr("intercept")
	if value != nil && *value != "" {
		var err error
		expression, err = filter.Parse(*value)
		if err != nil {
			return options.Errorf("Invalid filter expression: %s", pyrepr.Str(*value))
		}
	}
	i.filt = expression
	return i.options.Update(ctx, map[string]any{"intercept_active": expression != nil})
}

// ShouldIntercept reports whether f matches the active filter and is not replayed.
// It must be called under the addon dispatch lock.
func (i *Intercept) ShouldIntercept(f flow.Flow) bool {
	return i.options.Bool("intercept_active") && i.filt != nil && i.filt.Match(f) && (f.Common().IsReplay == nil || *f.Common().IsReplay == "")
}

func (i *Intercept) process(f flow.Flow) {
	if i.ShouldIntercept(f) {
		f.Common().Intercept()
	}
}

// Request processes an HTTP request.
func (i *Intercept) Request(_ context.Context, f *flow.HTTPFlow) error {
	i.process(f)
	return nil
}

// Response processes an HTTP response.
func (i *Intercept) Response(_ context.Context, f *flow.HTTPFlow) error {
	i.process(f)
	return nil
}

// TCPMessage processes a TCP message.
func (i *Intercept) TCPMessage(_ context.Context, f *flow.TCPFlow) error {
	i.process(f)
	return nil
}

// UDPMessage processes a UDP message.
func (i *Intercept) UDPMessage(_ context.Context, f *flow.UDPFlow) error {
	i.process(f)
	return nil
}

// DNSRequest processes a DNS query.
func (i *Intercept) DNSRequest(_ context.Context, f *flow.DNSFlow) error {
	i.process(f)
	return nil
}

// DNSResponse processes a DNS answer.
func (i *Intercept) DNSResponse(_ context.Context, f *flow.DNSFlow) error {
	i.process(f)
	return nil
}

// WebSocketMessage processes a WebSocket message.
func (i *Intercept) WebSocketMessage(_ context.Context, f *flow.HTTPFlow) error {
	i.process(f)
	return nil
}
