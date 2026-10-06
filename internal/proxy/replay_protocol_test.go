// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"testing"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestReplayProtocolBoundary(t *testing.T) {
	tests := map[string]struct {
		version string
		wantErr bool
	}{
		"success: HTTP1 reaches its protocol runner":       {version: "HTTP/1.1"},
		"success: saved HTTP2 reaches its protocol runner": {version: "HTTP/2.0"},
		"error: HTTP3 remains unsupported":                 {version: "HTTP/3", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			manager := newHookRunner(t).Manager
			f := testflow.TFlow()
			f.Request.HTTPVersion = tt.version
			called := false
			err := Replay(t.Context(), Config{Manager: manager, Options: options.New()}, f, nil, func(ctx context.Context, c *layer.Context, got *flow.HTTPFlow, mode hookdata.HTTPMode) error {
				called = true
				if got != f || mode != hookdata.HTTPModeTransparent {
					t.Errorf("runner flow = %p, mode = %v; want %p, transparent", got, mode, f)
				}
				if c.Data.Client == f.ClientConn || c.Data.Server == f.ServerConn {
					t.Error("replay reused live connection metadata instead of a snapshot")
				}
				return c.Do(ctx, func(context.Context) error {
					if got.Request.HTTPVersion != tt.version {
						t.Errorf("saved protocol changed to %q", got.Request.HTTPVersion)
					}
					return nil
				})
			})
			if tt.wantErr {
				if err == nil || err.Error() != "proxy: replay does not support HTTP/3" || called {
					t.Fatalf("HTTP3 runner called = %v, error = %v", called, err)
				}
			} else if err != nil || !called {
				t.Fatalf("runner called = %v, error = %v", called, err)
			}
		})
	}
}
