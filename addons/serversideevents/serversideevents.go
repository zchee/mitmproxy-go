// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package serversideevents warns about buffered server-side event responses.
package serversideevents

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/zchee/mitmproxy-go/flow"
)

// ServerSideEvents warns about unstreamed event responses without changing them.
// Its zero value is ready to register. It has no options or commands.
type ServerSideEvents struct{}

// Response warns when Content-Type starts with text/event-stream and neither
// Stream nor StreamFunc enables streaming. A missing response returns an error.
func (*ServerSideEvents) Response(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Response == nil {
		return errors.New("server_side_events: response is required")
	}
	if strings.HasPrefix(f.Response.Headers.Get("content-type"), "text/event-stream") && !f.Response.Stream && f.Response.StreamFunc == nil {
		slog.WarnContext(ctx, "mitmproxy currently does not support server side events. As a workaround, you can enable response streaming for such flows: https://github.com/mitmproxy/mitmproxy/issues/4469")
	}
	return nil
}
