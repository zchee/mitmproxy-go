// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package onboarding hosts the certificate installation app inside the proxy.
package onboarding

import (
	"context"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/apphost"
	"github.com/zchee/mitmproxy-go/addons/onboardingapp"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

// defaultHost is the hostname the installation app answers on until the
// onboarding_host option changes it.
const defaultHost = "mitm.it"

// Onboarding serves the certificate installation app for requests addressed
// to the configured onboarding host, on any port.
//
// Onboarding methods are called under the addon's dispatch lock.
type Onboarding struct {
	opts *options.Manager
	app  *apphost.App
}

// New returns an onboarding addon reading its configuration from opts.
func New(opts *options.Manager) *Onboarding {
	return &Onboarding{opts: opts, app: apphost.New(onboardingapp.New(opts), defaultHost, 0)}
}

// Load registers the onboarding and onboarding_host options.
func (o *Onboarding) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "onboarding", options.TypeBool, true, "Toggle the mitmproxy onboarding app."); err != nil {
		return err
	}
	return loader.AddOption(ctx, "onboarding_host", options.TypeStr, defaultHost, "Onboarding app domain. For transparent mode, use an IP when a DNS entry for the app domain is not present.")
}

// Configure points the hosted app at the configured onboarding host.
func (o *Onboarding) Configure(context.Context, map[string]struct{}) error {
	o.app.SetHost(o.opts.Str("onboarding_host"))
	return nil
}

// Request serves matching requests unless the onboarding option is off.
func (o *Onboarding) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if !o.opts.Bool("onboarding") {
		return nil
	}
	return o.app.Request(ctx, f)
}
