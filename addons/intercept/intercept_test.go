// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package intercept

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) (*Intercept, *addon.Manager) {
	t.Helper()
	opts := options.NewManager()
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	i := New(opts)
	must(t, manager.Add(t.Context(), i))
	return i, manager
}

func TestUpstreamSimple(t *testing.T) {
	i, manager := setup(t)
	must(t, manager.Do(t.Context(), func(context.Context) error {
		if i.filt != nil {
			t.Fatal("unexpected initial filter")
		}
		return nil
	}))
	must(t, manager.Options().Update(t.Context(), map[string]any{"intercept": new("~q")}))
	if !manager.Options().Bool("intercept_active") {
		t.Fatal("filter did not activate interception")
	}
	var optionError *options.OptionsError
	if err := manager.Options().Update(t.Context(), map[string]any{"intercept": new("~~")}); !errors.As(err, &optionError) || err.Error() != "Invalid filter expression: '~~'" {
		t.Fatalf("invalid filter error: %v", err)
	}
	must(t, manager.Options().Update(t.Context(), map[string]any{"intercept": (*string)(nil)}))
	must(t, manager.Do(t.Context(), func(context.Context) error {
		if i.filt != nil || manager.Options().Bool("intercept_active") {
			t.Fatal("clearing filter did not deactivate interception")
		}
		return nil
	}))
	must(t, manager.Options().Update(t.Context(), map[string]any{"intercept": new("~s")}))
	tests := map[string]struct {
		response bool
		active   bool
		want     bool
	}{
		"matching response": {true, true, true},
		"request only":      {false, true, false},
		"inactive response": {true, false, false},
		"reactivated":       {true, true, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			must(t, manager.Options().Update(t.Context(), map[string]any{"intercept_active": tt.active}))
			f := testflow.TFlow()
			if tt.response {
				f.Response = testflow.TResp()
			}
			must(t, manager.Trigger(t.Context(), addon.RequestHook{Flow: f}))
			if f.Response != nil {
				must(t, manager.Trigger(t.Context(), addon.ResponseHook{Flow: f}))
			}
			if diff := cmp.Diff(tt.want, f.Intercepted()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestUpstreamProtocols(t *testing.T) {
	tests := map[string]struct {
		filter string
		make   func() flow.Flow
		hooks  func(flow.Flow) []addon.Hook
	}{
		"test_dns": {"~s ~dns", func() flow.Flow { return testflow.TDNSFlow(testflow.WithResponse) }, func(f flow.Flow) []addon.Hook {
			return []addon.Hook{addon.DNSRequestHook{Flow: f.(*flow.DNSFlow)}, addon.DNSResponseHook{Flow: f.(*flow.DNSFlow)}}
		}},
		"test_tcp": {"~tcp", func() flow.Flow { return testflow.TTCPFlow() }, func(f flow.Flow) []addon.Hook {
			return []addon.Hook{addon.TCPMessageHook{Flow: f.(*flow.TCPFlow)}}
		}},
		"test_udp": {"~udp", func() flow.Flow { return testflow.TUDPFlow() }, func(f flow.Flow) []addon.Hook {
			return []addon.Hook{addon.UDPMessageHook{Flow: f.(*flow.UDPFlow)}}
		}},
		"test_websocket_message": {`~b "hello binary"`, func() flow.Flow { return testflow.TWebSocketFlow() }, func(f flow.Flow) []addon.Hook {
			return []addon.Hook{addon.WebSocketMessageHook{Flow: f.(*flow.HTTPFlow)}}
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, manager := setup(t)
			must(t, manager.Options().Update(t.Context(), map[string]any{"intercept": new(tt.filter)}))
			for _, active := range []bool{true, false} {
				must(t, manager.Options().Update(t.Context(), map[string]any{"intercept_active": active}))
				f := tt.make()
				for _, hook := range tt.hooks(f) {
					must(t, manager.Trigger(t.Context(), hook))
				}
				if diff := cmp.Diff(active, f.Common().Intercepted()); diff != "" {
					t.Fatal(diff)
				}
			}
			if name == "test_dns" {
				must(t, manager.Options().Update(t.Context(), map[string]any{"intercept_active": true}))
				f := testflow.TDNSFlow()
				must(t, manager.Trigger(t.Context(), addon.DNSRequestHook{Flow: f}))
				if f.Intercepted() {
					t.Fatal("response filter intercepted a query")
				}
			}
		})
	}
}

func TestReplayAndRollback(t *testing.T) {
	i, manager := setup(t)
	must(t, manager.Options().Update(t.Context(), map[string]any{"intercept": new("~all")}))
	for _, expr := range []string{"~~", "~h '", "\n"} {
		if err := manager.Options().Update(t.Context(), map[string]any{"intercept": new(expr)}); err == nil {
			t.Fatalf("accepted invalid expression %q", expr)
		}
		if got := manager.Options().OptStr("intercept"); got == nil || *got != "~all" {
			t.Fatal("filter option was not rolled back")
		}
	}
	tests := map[string]struct {
		replay *string
		want   bool
	}{"live": {nil, true}, "request replay": {new("request"), false}, "response replay": {new("response"), false}, "empty replay": {new(""), true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := testflow.TFlow()
			f.IsReplay = tt.replay
			must(t, manager.Do(t.Context(), func(context.Context) error {
				if diff := cmp.Diff(tt.want, i.ShouldIntercept(f)); diff != "" {
					t.Fatal(diff)
				}
				return nil
			}))
			must(t, manager.Trigger(t.Context(), addon.RequestHook{Flow: f}))
			if diff := cmp.Diff(tt.want, f.Intercepted()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	must(t, manager.Options().Update(t.Context(), map[string]any{"intercept": new("")}))
	if manager.Options().Bool("intercept_active") {
		t.Fatal("empty filter stayed active")
	}
}

func TestConcurrentDispatch(t *testing.T) {
	_, manager := setup(t)
	must(t, manager.Options().Update(t.Context(), map[string]any{"intercept": new("~all")}))
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			f := testflow.TFlow()
			if err := manager.Trigger(t.Context(), addon.RequestHook{Flow: f}); err != nil {
				t.Error(err)
			}
			if !f.Intercepted() {
				t.Error("concurrent flow was not intercepted")
			}
		})
	}
	wg.Wait()
}

func TestContract(t *testing.T) {
	_, manager := setup(t)
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{
		"intercept_active": {options.TypeBool, false, "Intercept toggle"},
		"intercept":        {options.TypeOptStr, (*string)(nil), "Intercept filter expression."},
	}
	items := manager.Options().Items()
	if len(items) != len(tests) {
		t.Fatal("unexpected option count")
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := manager.Options().Lookup(name)
			if !ok || opt.Type() != tt.typ || opt.Help() != tt.help || cmp.Diff(tt.def, opt.Default()) != "" {
				t.Fatalf("option mismatch: %s", name)
			}
		})
	}
	for name := range manager.Commands().Commands() {
		t.Fatalf("unexpected command %s", name)
	}
}
