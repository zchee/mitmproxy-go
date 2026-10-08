// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type poolCleanupValueKey struct{}

type poolCleanupAddon struct {
	wait func(context.Context) error
}

func (a *poolCleanupAddon) ServerConnectError(ctx context.Context, _ *hookdata.ServerConnection) error {
	return a.wait(ctx)
}

func (a *poolCleanupAddon) ServerDisconnected(ctx context.Context, _ *hookdata.ServerConnection) error {
	return a.wait(ctx)
}

func TestPoolCleanupExpiry(t *testing.T) {
	tests := map[string]struct{ operation string }{
		"connect failure":  {operation: "connect"},
		"upgrade metadata": {operation: "upgrade"},
		"disconnection":    {operation: "end"},
		"half close":       {operation: "half"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cause := errors.New("setup failed")
				observed := 0
				wait := func(ctx context.Context) error {
					observed++
					if diff := gocmp.Diff("retained", ctx.Value(poolCleanupValueKey{})); diff != "" {
						t.Errorf("cleanup value (-want +got):\n%s", diff)
					}
					deadline, ok := ctx.Deadline()
					if !ok {
						t.Error("cleanup context has no deadline")
						return errors.New("missing cleanup deadline")
					}
					if diff := gocmp.Diff(5*time.Second, time.Until(deadline)); diff != "" {
						t.Errorf("cleanup budget (-want +got):\n%s", diff)
					}
					if err := ctx.Err(); err != nil {
						t.Errorf("cleanup inherited cancellation: %v", err)
						return err
					}
					<-ctx.Done()
					// An addon may ignore its context error; the owner must still
					// expose the expired cleanup budget to its caller.
					return nil
				}
				runner := newHookRunner(t)
				if tt.operation == "connect" || tt.operation == "end" {
					if err := runner.Manager.Add(t.Context(), &poolCleanupAddon{wait: wait}); err != nil {
						t.Fatal(err)
					}
				}
				parent := context.WithValue(t.Context(), poolCleanupValueKey{}, "retained")
				pool := newServerPool(parent, connection.NewClient(connection.Address{}, connection.Address{}, 1), func(context.Context, *connection.Server) (layer.Conn, error) {
					return nil, cause
				}, runner, runner.Manager.Do)
				defer pool.cancel()
				entry := &poolEntry{srv: targetServer(), flight: &poolFlight{done: make(chan struct{})}}
				entry.state.Store(uint32(connection.Open))
				var err error
				switch tt.operation {
				case "connect":
					pool.cancel()
					err = pool.connectFailed(entry, cause)
				case "end":
					pool.cancel()
					err = pool.end(entry, cause)
				case "half":
					pool.cancel()
					pool.do = func(ctx context.Context, _ func(context.Context) error) error { return wait(ctx) }
					conn := &poolConn{pool: pool, entry: entry}
					err = conn.halfClose(connection.CanWrite)
				case "upgrade":
					raw, peer := net.Pipe()
					defer func() { _ = raw.Close() }()
					defer func() { _ = peer.Close() }()
					entry.flight.conn = &poolConn{Conn: memoryConn{Conn: raw, input: raw}, pool: pool, entry: entry}
					close(entry.flight.done)
					pool.entries = []*poolEntry{entry}
					var failed atomic.Bool
					pool.do = func(ctx context.Context, fn func(context.Context) error) error {
						if failed.Load() {
							return wait(ctx)
						}
						return runner.Manager.Do(ctx, fn)
					}
					_, _, err = pool.Upgrade(t.Context(), entry.srv, func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error) {
						pool.cancel()
						failed.Store(true)
						return nil, cause
					})
					pool.workers.Wait()
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("cleanup error = %v, want deadline exceeded", err)
				}
				if tt.operation != "half" && !errors.Is(err, cause) {
					t.Errorf("cleanup lost setup error: %v", err)
				}
				if diff := gocmp.Diff(1, observed); diff != "" {
					t.Errorf("cleanup observations (-want +got):\n%s", diff)
				}
			})
		})
	}
}

type poolCleanupConn struct {
	layer.Conn
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (c *poolCleanupConn) Close() error {
	if c.calls.Add(1) == 1 {
		close(c.entered)
	}
	<-c.release
	return c.Conn.Close()
}

func TestPoolCloseAllSharedOwner(t *testing.T) {
	tests := map[string]struct{ cancelCaller bool }{
		"cleanup budget expires": {},
		"first caller cancels":   {cancelCaller: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				raw, peer := net.Pipe()
				defer func() { _ = raw.Close() }()
				defer func() { _ = peer.Close() }()
				conn := &poolCleanupConn{Conn: memoryConn{Conn: raw, input: raw}, entered: make(chan struct{}), release: make(chan struct{})}
				runner := newHookRunner(t)
				pool := newServerPool(t.Context(), connection.NewClient(connection.Address{}, connection.Address{}, 1), func(context.Context, *connection.Server) (layer.Conn, error) { return conn, nil }, runner, runner.Manager.Do)
				flight := &poolFlight{done: make(chan struct{}), conn: conn}
				close(flight.done)
				pool.entries = []*poolEntry{{flight: flight}}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				first := make(chan error, 1)
				go func() { first <- pool.closeAll(ctx) }()
				<-conn.entered
				want := error(context.DeadlineExceeded)
				if tt.cancelCaller {
					cancel()
					want = context.Canceled
				} else {
					time.Sleep(5 * time.Second)
				}
				synctest.Wait()
				returned := false
				select {
				case err := <-first:
					returned = true
					if !errors.Is(err, want) {
						t.Errorf("first wait = %v, want %v", err, want)
					}
				default:
					t.Error("first caller remains blocked on transport cleanup")
				}
				select {
				case <-pool.closedDone:
					t.Error("unfinished cleanup published completion")
				default:
				}
				laterCtx, stop := context.WithTimeout(t.Context(), time.Second)
				defer stop()
				if err := pool.closeAll(laterCtx); !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("later wait = %v, want caller deadline exceeded", err)
				}
				if diff := gocmp.Diff(int32(1), conn.calls.Load()); diff != "" {
					t.Errorf("cleanup owners (-want +got):\n%s", diff)
				}
				close(conn.release)
				if !returned {
					<-first
				}
				if err := pool.closeAll(t.Context()); err != nil {
					t.Errorf("completed cleanup = %v", err)
				}
				if diff := gocmp.Diff(int32(1), conn.calls.Load()); diff != "" {
					t.Errorf("repeated cleanup (-want +got):\n%s", diff)
				}
			})
		})
	}
}
