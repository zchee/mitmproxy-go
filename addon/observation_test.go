// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestLifecycleObservation(t *testing.T) {
	tests := map[string]struct {
		nilCallback bool
		connection  bool
		yield       bool
		hookErr     error
		updateErr   error
		prepareErr  error
		dispatch    string
		want        []string
	}{
		"nil_callback":         {nilCallback: true, want: []string{"prepare", "hook", "update", "finish"}},
		"after_update":         {want: []string{"prepare", "hook", "update", "observe", "finish"}},
		"halt_observed":        {hookErr: ErrAddonHalt, want: []string{"prepare", "hook", "update", "observe", "finish"}},
		"connection_hook":      {connection: true, want: []string{"prepare", "observe", "finish"}},
		"once_not_update":      {want: []string{"prepare", "hook", "update", "observe", "finish"}},
		"trigger_excluded":     {dispatch: "trigger", want: []string{"hook"}},
		"invoke_sync_excluded": {dispatch: "invoke", want: []string{"hook"}},
		"prepare_failure":      {prepareErr: errors.New("prepare refused"), want: []string{"prepare"}},
		"dispatch_failure":     {hookErr: &options.OptionsError{Msg: "hook refused"}, want: []string{"prepare", "hook"}},
		"update_failure":       {updateErr: &options.OptionsError{Msg: "update refused"}, want: []string{"prepare", "hook", "update"}},
		"concurrent_refresh":   {yield: true, want: []string{"prepare", "hook", "update", "observe", "finish"}},
		"no_flow_mutation":     {want: []string{"prepare", "hook", "update", "observe", "finish"}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				f := flow.NewHTTPFlow(nil, nil, true)
				var order []string
				var observed int
				var m *Manager
				cfg := Config{Logger: slog.New(slog.DiscardHandler)}
				if !tt.nilCallback {
					cfg.OnHookComplete = func(ctx context.Context, hook Hook) {
						observed++
						order = append(order, "observe")
						if !m.d.valid(frameFrom(ctx)) {
							t.Error("observer received a stale frame")
						}
						if _, err := Concurrent(ctx, func(context.Context) error {
							t.Error("observer released dispatch")
							return nil
						}); !errors.Is(err, ErrSyncContext) {
							t.Errorf("observer Concurrent = %v, want synchronous rejection", err)
						}
						if tt.connection {
							if _, ok := hook.(ClientDisconnectedHook); !ok {
								t.Errorf("observed %T, want connection hook", hook)
							}
							return
						}
						if got := HookFlow(hook); got != f {
							t.Errorf("observed flow = %p, want %p", got, f)
						}
						if hook.Name() != "request" || f.Comment != "updated" {
							t.Errorf("observed hook=%s comment=%q, want original request after update", hook.Name(), f.Comment)
						}
					}
				}
				m = NewManager(options.NewManager(), command.NewManager(), cfg)
				t.Cleanup(m.Close)
				h := &mutationHook{
					onRequest: func(ctx context.Context, f *flow.HTTPFlow) error {
						order = append(order, "hook")
						if tt.yield {
							if _, err := Concurrent(ctx, func(context.Context) error { return nil }); err != nil {
								return err
							}
						}
						f.Comment = "handled"
						return tt.hookErr
					},
					onUpdate: func(ctx context.Context, _ []flow.Flow) error {
						order = append(order, "update")
						if tt.yield {
							if _, err := Concurrent(ctx, func(context.Context) error { return nil }); err != nil {
								return err
							}
						}
						f.Comment = "updated"
						return tt.updateErr
					},
				}
				if err := m.Add(t.Context(), h); err != nil {
					t.Fatal(err)
				}
				var hook Hook = RequestHook{Flow: f}
				if tt.connection {
					hook = ClientDisconnectedHook{}
				}
				var err error
				switch tt.dispatch {
				case "trigger":
					err = m.Trigger(t.Context(), hook)
				case "invoke":
					err = m.InvokeSync(t.Context(), h, hook)
				default:
					err = m.HookFunc(t.Context(), func(context.Context) error {
						order = append(order, "prepare")
						return tt.prepareErr
					}, hook, func(context.Context) {
						order = append(order, "finish")
						if !tt.connection && f.Comment != "updated" {
							t.Errorf("observer changed flow before finish: %q", f.Comment)
						}
					})
				}
				wantErr := tt.prepareErr
				if wantErr == nil && !errors.Is(tt.hookErr, ErrAddonHalt) {
					wantErr = tt.hookErr
				}
				if wantErr == nil {
					wantErr = tt.updateErr
				}
				if !errors.Is(err, wantErr) {
					t.Errorf("dispatch error = %v, want %v", err, wantErr)
				}
				if diff := gocmp.Diff(tt.want, order); diff != "" {
					t.Fatalf("lifecycle order (-want +got):\n%s", diff)
				}
				if observed > 1 {
					t.Errorf("observer called %d times for one lifecycle hook", observed)
				}
			})
		}
	})
}
