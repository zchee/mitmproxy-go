// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/master"
)

func webStateFixture(t *testing.T) (*master.Master, *ProxyServer) {
	t.Helper()
	m, ps, _, _ := fixture(t, false)
	t.Cleanup(func() {
		for _, instance := range ps.instances.Load().instances {
			_ = instance.Stop()
		}
	})
	return m, ps
}

func TestWebServerState(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"transitions/reconcile":             {run: testWebStateReconcile},
		"transitions/wireguard_monitor":     {run: func(t *testing.T) { testWebStateMonitor(t, "wireguard", "wireguard_conf", "client configuration") }},
		"transitions/tun_monitor":           {run: func(t *testing.T) { testWebStateMonitor(t, "tun", "tun_name", "controlled-tun") }},
		"transitions/local_monitor":         {run: func(t *testing.T) { testWebStateMonitor(t, "local", "", "") }},
		"transitions/instance_cancellation": {run: func(t *testing.T) { testWebStateMonitor(t, "regular", "", "") }},
		"transitions/proxy_shutdown":        {run: testWebStateShutdown},
		"ordering/two_reconciliations":      {run: testWebStateOrdering},
		"ordering/dispatch_snapshot_read":   {run: testWebStateDispatchRead},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}

func testWebStateReconcile(t *testing.T) {
	m, ps := webStateFixture(t)
	if err := ps.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := ps.ServerSnapshot()
	if first.Generation == 0 || len(first.Servers) != 1 {
		t.Fatalf("initial publication = %+v", first)
	}
	for _, raw := range first.Servers {
		var state map[string]any
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		if state["is_running"] != true || state["last_exception"] != nil {
			t.Fatalf("running state = %s", raw)
		}
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	spec := "regular@" + occupied.Addr().String()
	update(t, m, map[string]any{"mode": []string{spec}})
	if err := ps.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	failed := ps.ServerSnapshot()
	var state map[string]any
	if err := json.Unmarshal(failed.Servers[spec], &state); err != nil {
		t.Fatal(err)
	}
	if failed.Generation <= first.Generation || state["is_running"] != false || state["last_exception"] == nil {
		t.Fatalf("bind failure publication = %+v, %s", failed, failed.Servers[spec])
	}
	update(t, m, map[string]any{"server": false})
	if err := ps.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	stopped := ps.ServerSnapshot()
	if stopped.Generation <= failed.Generation || len(stopped.Servers) != 0 {
		t.Fatalf("stop publication = %+v", stopped)
	}
	if len(first.Servers) != 1 {
		t.Fatal("retained snapshot changed after reconcile")
	}
}

// Monitor transitions are injected completed presentation publications here.
// The source-specific monitor and cancellation paths are exercised in modeserver.
func testWebStateMonitor(t *testing.T, kind, field, value string) {
	m, ps := webStateFixture(t)
	states := make(chan ServerSnapshot, 4)
	if err := m.Do(t.Context(), func(context.Context) error {
		ps.SubscribeServerState(func(_ context.Context, state ServerSnapshot) {
			if !ps.updateMu.TryLock() {
				t.Error("notification held lifecycle lock")
			} else {
				ps.updateMu.Unlock()
			}
			select {
			case states <- state:
			default:
				t.Error("unexpected duplicate publication")
			}
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mode, err := modespec.Parse(kind)
	if err != nil {
		t.Fatal(err)
	}
	spec := mode.String()
	for index, running := range []bool{true, false} {
		var failure any
		if !running {
			failure = "controlled source ended"
		}
		state := map[string]any{"type": mode.Name(), "description": mode.Description(), "full_spec": spec, "is_running": running, "last_exception": failure, "listen_addrs": [][2]any{}}
		if field != "" {
			state[field] = nil
			if running {
				state[field] = value
			}
		}
		raw, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		ps.updateMu.Lock()
		ps.presentation.Store(&ServerSnapshot{Generation: uint64(index + 1), Servers: map[string]jsontext.Value{spec: raw}})
		ps.updateMu.Unlock()
		ps.deliverServerState(t.Context())
		got := await(t, states)
		if diff := cmp.Diff(ps.ServerSnapshot(), got); diff != "" {
			t.Fatalf("state/update differs from accessor (-want +got):\n%s", diff)
		}
		wire, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(bytes.ToLower(wire), []byte("generation")) {
			t.Fatalf("internal ordering metadata on wire: %s", wire)
		}
		got.Servers[spec][0] = '!'
		delete(got.Servers, spec)
		if diff := cmp.Diff(jsontext.Value(raw), ps.ServerSnapshot().Servers[spec]); diff != "" {
			t.Fatalf("caller mutation changed publication: %s", diff)
		}
	}
	ps.deliverServerState(t.Context())
	select {
	case got := <-states:
		t.Fatalf("stale publication redelivered: %+v", got)
	default:
	}
}

func testWebStateShutdown(t *testing.T) {
	m, ps := webStateFixture(t)
	states := make(chan ServerSnapshot, 8)
	if err := m.Do(t.Context(), func(context.Context) error {
		ps.SubscribeServerState(func(_ context.Context, state ServerSnapshot) { states <- state })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := ps.SetupServers(t.Context()); err != nil {
		t.Fatal(err)
	}
	live := await(t, states)
	if len(live.Servers) != 1 {
		t.Fatalf("live snapshot = %+v", live)
	}
	if err := m.Do(t.Context(), ps.Done); err != nil {
		t.Fatal(err)
	}
	ps.workers.Wait()
	stopped := await(t, states)
	if stopped.Generation <= live.Generation || len(stopped.Servers) != 0 {
		t.Fatalf("shutdown snapshot = %+v", stopped)
	}
	if diff := cmp.Diff(stopped, ps.ServerSnapshot()); diff != "" {
		t.Fatal(diff)
	}
}

func testWebStateOrdering(t *testing.T) {
	m, ps := webStateFixture(t)
	var delivered []ServerSnapshot
	if err := m.Do(t.Context(), func(context.Context) error {
		ps.SubscribeServerState(func(_ context.Context, state ServerSnapshot) { delivered = append(delivered, state) })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := ps.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := ps.ServerSnapshot()
	update(t, m, map[string]any{"mode": []string{"socks5@127.0.0.1:0"}})
	if err := ps.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	second := ps.ServerSnapshot()
	if second.Generation <= first.Generation {
		t.Fatal("reconciliation did not advance generation")
	}
	// Deliver the first reconciliation's delayed invalidation after the second
	// has completed. Reading the current publication must suppress the old one.
	ps.deliverServerState(t.Context())
	ps.deliverServerState(t.Context())
	if diff := cmp.Diff([]ServerSnapshot{second}, delivered); diff != "" {
		t.Fatalf("delayed delivery regressed (-want +got):\n%s", diff)
	}
	if _, ok := first.Servers["socks5@127.0.0.1:0"]; ok {
		t.Fatal("retained generation mixed with replacement instance")
	}
}

func testWebStateDispatchRead(t *testing.T) {
	m, ps := webStateFixture(t)
	if err := ps.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := ps.ServerSnapshot()
	ps.updateMu.Lock()
	defer ps.updateMu.Unlock()
	read := make(chan error, 1)
	go func() {
		read <- m.Do(t.Context(), func(context.Context) error {
			if diff := cmp.Diff(want, ps.ServerSnapshot()); diff != "" {
				t.Error(diff)
			}
			return nil
		})
	}()
	// The read must complete while lifecycle work remains deliberately locked.
	err := await(t, read)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServerStateObserverLifetime(t *testing.T) {
	tests := map[string]struct{}{"unsubscribe and independent snapshot ownership": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			m, ps := webStateFixture(t)
			if err := ps.reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			var calls int
			if err := m.Do(t.Context(), func(context.Context) error {
				ps.SubscribeServerState(nil)()
				unsubscribe := ps.SubscribeServerState(func(context.Context, ServerSnapshot) { calls++ })
				unsubscribe()
				unsubscribe()
				ps.SubscribeServerState(func(_ context.Context, state ServerSnapshot) { clear(state.Servers) })
				ps.SubscribeServerState(func(_ context.Context, state ServerSnapshot) {
					if len(state.Servers) != 1 {
						t.Error("another subscriber changed owned data")
					}
					calls++
				})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			ps.deliverServerState(t.Context())
			if calls != 1 || len(ps.ServerSnapshot().Servers) != 1 {
				t.Fatalf("observer calls=%d", calls)
			}
		})
	}
}
