// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver

import (
	"context"
	json "encoding/json/v2"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy/modeserver"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func TestServerStateObserverUnsubscribeDuringCallback(t *testing.T) {
	tests := map[string]struct{}{"self and another callback finish captured delivery": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			m, ps := webStateFixture(t)
			if err := ps.reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			var first, second int
			var stopFirst, stopSecond func()
			if err := m.Do(t.Context(), func(context.Context) error {
				stopFirst = ps.SubscribeServerState(func(context.Context, ServerSnapshot) { first++; stopFirst(); stopSecond(); stopFirst(); stopSecond() })
				stopSecond = ps.SubscribeServerState(func(context.Context, ServerSnapshot) { second++ })
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			ps.deliverServerState(t.Context())
			if first != 1 || second != 1 {
				t.Fatalf("captured callbacks = %d, %d", first, second)
			}
			update(t, m, map[string]any{"server": false})
			if err := ps.reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			ps.deliverServerState(t.Context())
			if first != 1 || second != 1 {
				t.Fatalf("unsubscribed callbacks ran: %d, %d", first, second)
			}
			if err := m.Do(t.Context(), func(context.Context) error { stopFirst(); stopSecond(); return nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServerStateRefreshRace(t *testing.T) {
	tests := map[string]struct{}{"completion after dequeue advances the published generation": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			m, ps := webStateFixture(t)
			mode, err := modespec.Parse("regular@127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			instance, err := modeserver.New(mode, modeserver.Config{Handler: ps.handler, PresentationChanged: ps.presentationWake, PresentationRevision: &ps.presentationRevision})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if err := instance.Start(ctx); err != nil {
				t.Fatal(err)
			}
			ps.instances.Store(&serverState{instances: []*modeserver.Instance{instance}})
			ps.updateMu.Lock()
			ps.publishServerState()
			ps.updateMu.Unlock()
			live := ps.ServerSnapshot()
			deliveries := make(chan ServerSnapshot, 1)
			if err := m.Do(t.Context(), func(context.Context) error {
				ps.SubscribeServerState(func(_ context.Context, state ServerSnapshot) { deliveries <- state })
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			ps.updateMu.Lock()
			locked := true
			defer func() {
				if locked {
					ps.updateMu.Unlock()
				}
			}()
			dequeued := make(chan uint64, 1)
			completed := make(chan struct{})
			go func() {
				defer close(completed)
				<-ps.presentationWake
				revision := ps.presentationRevision.Load()
				dequeued <- revision
				ps.refreshServerState(revision)
			}()
			t.Cleanup(func() { await(t, completed) })
			before := await(t, dequeued)
			cancel()
			// Consume the coalescible invalidation while publication is gated. The
			// captured revision must still detect the completed instance change.
			await(t, ps.presentationWake)
			if ps.presentationRevision.Load() <= before {
				t.Fatal("source signalled before advancing its revision")
			}
			ps.updateMu.Unlock()
			locked = false
			await(t, completed)
			current := ps.ServerSnapshot()
			if current.Generation <= live.Generation {
				t.Fatal("completed source publication did not advance generation")
			}
			var state map[string]any
			if err := json.Unmarshal(current.Servers[mode.String()], &state); err != nil {
				t.Fatal(err)
			}
			if state["is_running"] != false || state["last_exception"] != nil {
				t.Fatal("completion racing refresh left an incomplete presentation")
			}
			ps.deliverServerState(t.Context())
			if got := await(t, deliveries); got.Generation != current.Generation {
				t.Fatal("state/update did not deliver the completed generation")
			}
		})
	}
}
