// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package master_test

import (
	"context"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/master"
)

func TestObservationConfig(t *testing.T) {
	tests := map[string]struct {
		holdCallbacks bool
		want          []string
	}{
		"forwarded":              {want: []string{"observe"}},
		"chained_hold_callbacks": {holdCallbacks: true, want: []string{"existing_start", "telemetry_start", "observe", "telemetry_end", "existing_end"}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				var order []string
				f := flow.NewHTTPFlow(nil, nil, true)
				cfg := master.Config{Logger: discard}
				if tt.holdCallbacks {
					cfg.OnDispatchStart = func() {
						order = append(order, "existing_start", "telemetry_start")
					}
					cfg.OnDispatchEnd = func() {
						order = append(order, "telemetry_end", "existing_end")
					}
				}
				cfg.OnHookComplete = func(ctx context.Context, hook addon.Hook) {
					order = append(order, "observe")
					if hook.Name() != "request" || addon.HookFlow(hook) != f {
						t.Errorf("forwarded hook = %#v, want original request", hook)
					}
					if _, err := addon.Concurrent(ctx, func(context.Context) error {
						t.Error("observer released dispatch")
						return nil
					}); !errors.Is(err, addon.ErrSyncContext) {
						t.Errorf("observer Concurrent = %v, want synchronous frame", err)
					}
				}
				m := master.New(cfg)
				t.Cleanup(func() {
					if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
						t.Error(err)
					}
				})
				if err := m.Addons.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(tt.want, order); diff != "" {
					t.Fatalf("observation config (-want +got):\n%s", diff)
				}
			})
		}
	})
}
