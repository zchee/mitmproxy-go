// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package disableh2c refuses HTTP/2 upgrades and prior knowledge without TLS.
package disableh2c

import (
	"context"
	"log/slog"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
)

// DisableH2C strips exact h2c upgrade headers and kills live prior-knowledge flows.
type DisableH2C struct{}

// New returns a cleartext HTTP/2 rejection addon.
func New() *DisableH2C { return &DisableH2C{} }

// Name returns the upstream addon name.
func (*DisableH2C) Name() string { return "disableh2c" }

// Request removes h2c upgrades and rejects the HTTP/2 cleartext connection preface.
func (*DisableH2C) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Request.Headers.Get("upgrade") == "h2c" {
		slog.WarnContext(ctx, "HTTP/2 cleartext connections (h2c upgrade requests) are currently not supported.")
		f.Request.Headers.Del("upgrade")
		f.Request.Headers.Del("connection")
		f.Request.Headers.Del("http2-settings")
	}
	if strings.ToUpper(f.Request.Method) == "PRI" && f.Request.Path == "*" && f.Request.HTTPVersion == "HTTP/2.0" {
		if f.Killable() {
			if err := f.Kill(); err != nil {
				return err
			}
		}
		slog.WarnContext(ctx, "Initiating HTTP/2 connections with prior knowledge are currently not supported.")
	}
	return nil
}

var _ addon.RequestHandler = (*DisableH2C)(nil)
