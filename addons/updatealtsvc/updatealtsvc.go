// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package updatealtsvc retargets reverse-proxy Alt-Svc advertisements to the listener.
package updatealtsvc

import (
	"context"
	"errors"
	"strconv"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter/regex"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/options"
)

var hostPattern = func() *regex.Pattern {
	pattern, err := regex.CompilePattern(`([a-zA-Z0-9.-]*:\d{1,5})`, regex.Unicode)
	if err != nil {
		panic("updatealtsvc: invalid built-in host pattern: " + err.Error())
	}
	return pattern
}()

func updateHeader(header string, port int) (string, error) {
	return hostPattern.SubString(":"+strconv.Itoa(port), header, 0)
}

// UpdateAltSvc rewrites reverse-mode Alt-Svc headers unless explicitly retained.
// Rewrites use the shared regex package's 256 MiB input/output bounds.
type UpdateAltSvc struct{ options *options.Manager }

// New returns an Alt-Svc rewriting addon using opts.
func New(opts *options.Manager) *UpdateAltSvc { return &UpdateAltSvc{options: opts} }

// Name returns the upstream addon name.
func (*UpdateAltSvc) Name() string { return "updatealtsvc" }

// Load registers the upstream keep_alt_svc_header option.
func (*UpdateAltSvc) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "keep_alt_svc_header", options.TypeBool, false, "Reverse Proxy: Keep Alt-Svc headers as-is, even if they do not point to mitmproxy. Enabling this option may cause clients to bypass the proxy.")
}

// ResponseHeaders rewrites every advertised host/port to the actual listener port
// in reverse mode. Repeated Alt-Svc fields are folded before rewriting, as upstream.
func (u *UpdateAltSvc) ResponseHeaders(_ context.Context, f *flow.HTTPFlow) error {
	if f.Response == nil {
		return errors.New("updatealtsvc: response is required")
	}
	if u.options.Bool("keep_alt_svc_header") || !f.Response.Headers.Has("alt-svc") {
		return nil
	}
	if f.ClientConn == nil {
		return errors.New("updatealtsvc: client connection is required")
	}
	mode, err := modespec.Parse(f.ClientConn.ProxyMode)
	if err != nil {
		return nil
	}
	if _, reverse := mode.(modespec.ReverseMode); !reverse {
		return nil
	}
	if f.ClientConn.Sockname == nil {
		return errors.New("updatealtsvc: client socket address is required")
	}
	rewritten, err := updateHeader(f.Response.Headers.Get("alt-svc"), f.ClientConn.Sockname.Port)
	if err != nil {
		return err
	}
	f.Response.Headers.Set("alt-svc", rewritten)
	return nil
}

var (
	_ addon.LoadHandler            = (*UpdateAltSvc)(nil)
	_ addon.ResponseHeadersHandler = (*UpdateAltSvc)(nil)
)
