// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/tcp"
)

func TestHandlerRejectsDeadFlow(t *testing.T) {
	f := startHandler(t, func(ctx context.Context, _ *layer.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	defer func() { f.connections.Close(); _ = await(t, f.done) }()
	dead := flow.NewTCPFlow(&connection.Client{ID: f.id(t)}, nil, false)
	if err := f.handler.Inject(t.Context(), layer.Injected{Flow: dead, Message: &tcp.Message{}}); !errors.Is(err, ErrFlowNotLive) {
		t.Fatalf("injection into completed flow: %v, want %v", err, ErrFlowNotLive)
	}
}

func TestHandlerInjectionInsideDispatch(t *testing.T) {
	f := startHandler(t, func(ctx context.Context, _ *layer.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	id := f.id(t)
	if err := f.handler.manager.Do(t.Context(), func(ctx context.Context) error {
		live := flow.NewTCPFlow(&connection.Client{ID: id}, nil, true)
		for range injectionCapacity {
			if err := f.handler.Inject(ctx, layer.Injected{Flow: live, Message: &tcp.Message{}}); err != nil {
				return err
			}
		}
		if err := f.handler.Inject(ctx, layer.Injected{Flow: live, Message: &tcp.Message{}}); !errors.Is(err, ErrInjectionFull) {
			t.Errorf("full queue while dispatch held: %v", err)
		}
		snapshot, err := f.connections.Snapshot(ctx)
		if err != nil {
			return err
		}
		snapshot[0].ProxyMode = "modified snapshot"
		f.connections.Close()
		// Teardown needs dispatch; Close must not wait for it here.
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := await(t, f.done); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerServerActivity(t *testing.T) {
	tests := map[string]struct{ write bool }{"read": {}, "write": {write: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			opened, activity := make(chan context.Context, 1), make(chan error, 1)
			read := make(chan struct{})
			bind := &bindAddon{t: t, ids: make(chan string, 1), run: func(ctx context.Context, c *layer.Context) error {
				conn, _, err := c.Pool.Open(ctx, targetServer(), layer.OpenOptions{Reuse: true})
				if err != nil {
					activity <- err
					return err
				}
				opened <- ctx
				<-read
				if tt.write {
					_, err = conn.Write([]byte("x"))
				} else {
					_, err = io.ReadFull(conn, make([]byte, 1))
				}
				activity <- err
				<-ctx.Done()
				return ctx.Err()
			}}
			runner := newHookRunner(t, bind)
			if err := runner.Manager.Options().Update(t.Context(), map[string]any{"tcp_timeout": 5}); err != nil {
				t.Fatal(err)
			}
			dialer := &poolDialer{t: t}
			h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: &Connections{}, Dialer: dialer.dial})
			if err != nil {
				t.Fatal(err)
			}
			h.clock = clock
			_, proxySide := layertest.Pipe(t)
			done := make(chan error, 1)
			go func() { done <- h.Handle(t.Context(), proxySide, "regular", hookdata.LayerSpec{Kind: topKind}) }()
			ctx := await(t, opened)
			clock.advance(4 * time.Second)
			close(read)
			peer := make(chan error, 1)
			go func() {
				var err error
				if tt.write {
					_, err = io.ReadFull(dialer.peer(0), make([]byte, 1))
				} else {
					_, err = dialer.peer(0).Write([]byte("x"))
				}
				peer <- err
			}()
			if err := await(t, peer); err != nil {
				t.Fatal(err)
			}
			if err := await(t, activity); err != nil {
				t.Fatal(err)
			}
			clock.advance(4 * time.Second)
			if ctx.Err() != nil {
				t.Error("upstream activity did not extend the idle deadline")
			}
			clock.advance(time.Second)
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandlerHookWatchdogWiring(t *testing.T) {
	tests := map[string]struct{ intercept bool }{"hook": {}, "intercept": {intercept: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			entered, released := make(chan context.Context, 1), make(chan context.Context, 1)
			resume := make(chan struct{})
			f := flow.NewHTTPFlow(nil, nil, true)
			bind := &bindAddon{t: t, ids: make(chan string, 1), run: func(ctx context.Context, c *layer.Context) error {
				if _, err := c.Hooks.Fire(ctx, addon.RequestHook{Flow: f}); err != nil {
					return err
				}
				released <- ctx
				<-ctx.Done()
				return ctx.Err()
			}}
			runner := newHookRunner(t, bind, &runnerAddon{request: func(ctx context.Context, _ *flow.HTTPFlow) error {
				if tt.intercept {
					f.Intercept()
				}
				entered <- ctx
				if !tt.intercept {
					<-resume
				}
				return nil
			}})
			if err := runner.Manager.Options().Update(t.Context(), map[string]any{"tcp_timeout": 5}); err != nil {
				t.Fatal(err)
			}
			h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: &Connections{}})
			if err != nil {
				t.Fatal(err)
			}
			h.clock = clock
			_, proxySide := layertest.Pipe(t)
			done := make(chan error, 1)
			go func() {
				done <- h.Handle(t.Context(), proxySide, "regular@127.0.0.1:8081", hookdata.LayerSpec{Kind: topKind})
			}()
			ctx := await(t, entered)
			clock.advance(30 * time.Second)
			if ctx.Err() != nil {
				t.Error("watchdog expired during hook or intercept wait")
			}
			if tt.intercept {
				if err := runner.Manager.Do(t.Context(), func(context.Context) error { f.Resume(); return nil }); err != nil {
					t.Fatal(err)
				}
			} else {
				close(resume)
			}
			ctx = await(t, released)
			snapshot, err := h.connections.Snapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("regular@127.0.0.1:8081", snapshot[0].ProxyMode); diff != "" {
				t.Fatalf("full mode spec (-want +got):\n%s", diff)
			}
			clock.advance(4 * time.Second)
			if ctx.Err() != nil {
				t.Error("watchdog expired before rearmed deadline")
			}
			clock.advance(time.Second)
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
