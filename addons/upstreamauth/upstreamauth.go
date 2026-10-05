// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package upstreamauth adds HTTP Basic credentials to upstream and reverse requests.
package upstreamauth

import (
	"context"
	"encoding/base64"
	"regexp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/options"
)

var authPattern = regexp.MustCompile(`.+:`)

// UpstreamAuth supplies configured credentials to upstream systems.
// Its hooks must run within an addon.Manager dispatch domain.
type UpstreamAuth struct {
	opts *options.Manager
	auth string
}

// New returns an upstream authentication addon using opts.
func New(opts *options.Manager) *UpstreamAuth { return &UpstreamAuth{opts: opts} }

// Load registers the upstream_auth option.
func (a *UpstreamAuth) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "upstream_auth", options.TypeOptStr, (*string)(nil), "Add HTTP Basic authentication to upstream proxy and reverse proxy requests. Format: username:password.")
}

// Configure validates credentials before replacing the active header value.
func (a *UpstreamAuth) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["upstream_auth"]; !ok {
		return nil
	}
	spec := a.opts.OptStr("upstream_auth")
	if spec == nil {
		a.auth = ""
		return nil
	}
	if !authPattern.MatchString(*spec) {
		return options.Errorf("Invalid upstream auth specification.")
	}
	a.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(*spec))
	return nil
}

// HTTPConnectUpstream adds credentials to an upstream CONNECT request.
func (a *UpstreamAuth) HTTPConnectUpstream(_ context.Context, f *flow.HTTPFlow) error {
	if a.auth != "" {
		f.Request.Headers.Set("Proxy-Authorization", a.auth)
	}
	return nil
}

// RequestHeaders adds credentials without exposing them inside an upstream tunnel.
func (a *UpstreamAuth) RequestHeaders(_ context.Context, f *flow.HTTPFlow) error {
	if a.auth == "" {
		return nil
	}
	mode, err := modespec.Parse(f.ClientConn.ProxyMode)
	if err != nil {
		return err
	}
	if mode.Name() == "upstream" && f.Request.Scheme == "http" {
		f.Request.Headers.Set("Proxy-Authorization", a.auth)
	} else if mode.Name() == "reverse" {
		f.Request.Headers.Set("Authorization", a.auth)
	}
	return nil
}
