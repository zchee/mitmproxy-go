// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package keepserving

import (
	"context"
	"errors"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
)

func TestCancelledRunningDoesNotStartWatcher(t *testing.T) {
	tests := map[string]struct {
		sync bool
	}{
		"error: cancelled ordinary hook":    {},
		"error: cancelled synchronous hook": {sync: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, k, _ := newServing(t, 0)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"rfile": new("flows")})
			}); err != nil {
				t.Fatal(err)
			}
			err := m.Do(t.Context(), func(ctx context.Context) error {
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				var err error
				if tt.sync {
					err = m.Addons.InvokeSync(ctx, k, addon.RunningHook{})
				} else {
					err = k.Running(ctx)
				}
				if k.cancel != nil || k.done != nil {
					t.Error("cancelled running hook started a watcher")
				}
				return err
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Running = %v, want context.Canceled", err)
			}
		})
	}
}
