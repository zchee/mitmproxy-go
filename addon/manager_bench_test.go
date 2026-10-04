// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// benchAddon handles running and request and does nothing else, so that a
// benchmark measures the dispatch itself.
type benchAddon struct{ name string }

func (a *benchAddon) Name() string                                { return a.name }
func (*benchAddon) Running(context.Context) error                 { return nil }
func (*benchAddon) Request(context.Context, *flow.HTTPFlow) error { return nil }

// benchManager returns a Manager with n addons in its chain.
func benchManager(b *testing.B, n int) *addon.Manager {
	b.Helper()
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{Logger: slog.New(slog.DiscardHandler)})
	b.Cleanup(m.Close)
	for i := range n {
		if err := m.Add(b.Context(), &benchAddon{name: fmt.Sprintf("a%d", i)}); err != nil {
			b.Fatalf("Add: %v", err)
		}
	}
	return m
}

// BenchmarkTrigger dispatches a hook without a flow to a chain of addons.
func BenchmarkTrigger(b *testing.B) {
	for _, n := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("addons=%d", n), func(b *testing.B) {
			m := benchManager(b, n)
			ctx := b.Context()
			b.ReportAllocs()
			for b.Loop() {
				if err := m.Trigger(ctx, addon.RunningHook{}); err != nil {
					b.Fatalf("Trigger: %v", err)
				}
			}
		})
	}
}

// BenchmarkHook dispatches a flow hook, which also fires update, to a chain
// of addons, as the proxy does for every lifecycle event of a flow.
func BenchmarkHook(b *testing.B) {
	for _, n := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("addons=%d", n), func(b *testing.B) {
			m := benchManager(b, n)
			ctx := b.Context()
			hook := addon.RequestHook{Flow: testflow.TFlow()}
			b.ReportAllocs()
			for b.Loop() {
				if err := m.Hook(ctx, hook); err != nil {
					b.Fatalf("Hook: %v", err)
				}
			}
		})
	}
}
