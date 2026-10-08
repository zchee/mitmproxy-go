// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestPoolFailureCacheBound(t *testing.T) {
	tests := map[string]struct{ upgrade bool }{
		"connection failures": {},
		"upgrade failure":     {upgrade: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			failure := errors.New("origin refused connection")
			var calls atomic.Int32
			pool, _ := newPool(t, func(context.Context, *connection.Server) (layer.Conn, error) {
				if calls.Add(1) == 1 && tt.upgrade {
					raw, peer := net.Pipe()
					t.Cleanup(func() { _ = raw.Close(); _ = peer.Close() })
					return memoryConn{Conn: raw, input: raw}, nil
				}
				return nil, failure
			})
			oldest := targetServer()
			if tt.upgrade {
				_, srv, err := pool.Open(t.Context(), oldest, layer.OpenOptions{Reuse: true})
				if err != nil {
					t.Fatal(err)
				}
				pool.workers.Wait()
				if _, _, err := pool.Upgrade(t.Context(), srv, func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error) { return nil, failure }); !errors.Is(err, failure) {
					t.Fatalf("upgrade failure = %v", err)
				}
			} else if _, _, err := pool.Open(t.Context(), oldest, layer.OpenOptions{Reuse: true}); !errors.Is(err, failure) {
				t.Fatalf("initial failure = %v", err)
			}
			pool.workers.Wait()
			for i := range 256 {
				srv := targetServer()
				srv.Address.Port += i + 1
				if _, _, err := pool.Open(t.Context(), srv, layer.OpenOptions{Reuse: true}); !errors.Is(err, failure) {
					t.Fatalf("failed key %d = %v", i, err)
				}
				pool.workers.Wait()
			}
			pool.mu.Lock()
			retained := len(pool.entries)
			pool.mu.Unlock()
			if diff := gocmp.Diff(256, retained); diff != "" {
				t.Errorf("completed failed entries (-want +got):\n%s", diff)
			}
			recent := targetServer()
			recent.Address.Port += 256
			if _, _, err := pool.Open(t.Context(), recent, layer.OpenOptions{Reuse: true}); !errors.Is(err, failure) {
				t.Fatalf("recent cached failure = %v", err)
			}
			if diff := gocmp.Diff(int32(257), calls.Load()); diff != "" {
				t.Errorf("recent failure redialed (-want +got):\n%s", diff)
			}
			if _, _, err := pool.Open(t.Context(), oldest, layer.OpenOptions{Reuse: true}); !errors.Is(err, failure) {
				t.Fatalf("oldest redial failure = %v", err)
			}
			pool.workers.Wait()
			if diff := gocmp.Diff(int32(258), calls.Load()); diff != "" {
				t.Errorf("oldest key was not redialed (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPoolFailureWaitersRetained(t *testing.T) {
	tests := map[string]struct {
		failed  bool
		retired bool
	}{
		"failed flight waiters":     {failed: true},
		"established lease":         {},
		"retired established lease": {retired: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			failure := errors.New("origin refused connection")
			entered, release := make(chan struct{}), make(chan struct{})
			raw, peer := net.Pipe()
			defer func() { _ = raw.Close(); _ = peer.Close() }()
			var calls atomic.Int32
			pool, _ := newPool(t, func(ctx context.Context, srv *connection.Server) (layer.Conn, error) {
				calls.Add(1)
				if srv.Address.Port == 443 {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					if !tt.failed {
						return memoryConn{Conn: raw, input: raw}, nil
					}
				}
				return nil, failure
			})
			oldest := targetServer()
			entry, winner, err := pool.claim(t.Context(), keyOf(oldest), oldest, oldest, layer.OpenOptions{Reuse: true})
			if err != nil || !winner {
				t.Fatalf("initial flight = (%t, %v)", winner, err)
			}
			<-entered
			waiter, winner, err := pool.claim(t.Context(), keyOf(oldest), targetServer(), oldest, layer.OpenOptions{Reuse: true})
			if err != nil || winner || waiter != entry {
				t.Fatalf("joined flight = (%t, %v, same %t)", winner, err, waiter == entry)
			}
			if tt.retired {
				pool.Retire(oldest)
			}
			releaseFlight := sync.OnceFunc(func() { close(release) })
			defer releaseFlight()
			if !tt.failed {
				releaseFlight()
				pool.workers.Wait()
			}
			for i := range 257 {
				srv := targetServer()
				srv.Address.Port += i + 1
				_, _, err := pool.Open(t.Context(), srv, layer.OpenOptions{Reuse: true})
				if !errors.Is(err, failure) {
					t.Fatalf("failed key %d = %v", i, err)
				}
				// The failed flight stays blocked while completed failures
				// are evicted; established leases must also remain tracked.
				pool.mu.Lock()
				inflightRetained := pool.find(oldest) == entry
				pool.mu.Unlock()
				if !inflightRetained {
					t.Fatal("in-flight entry was evicted")
				}
			}
			results := make(chan openResult, 2)
			for _, retained := range []*poolEntry{entry, waiter} {
				go func() {
					conn, err := pool.await(t.Context(), retained)
					results <- openResult{conn: conn, err: err}
				}()
			}
			releaseFlight()
			var lease layer.Conn
			for range 2 {
				result := await(t, results)
				if tt.failed {
					if !errors.Is(result.err, failure) {
						t.Errorf("retained waiter lost flight result: %v", result.err)
					}
					continue
				}
				if result.err != nil || result.conn == nil {
					t.Fatalf("established waiter = (%v, %v)", result.conn, result.err)
				}
				if lease != nil && result.conn != lease {
					t.Error("waiters received different leases")
				}
				lease = result.conn
			}
			pool.workers.Wait()
			if lease != nil {
				pool.mu.Lock()
				retained := pool.find(oldest) == entry
				pool.mu.Unlock()
				if !retained {
					t.Error("established lease was evicted")
				}
				read := make(chan error, 1)
				go func() { var b [1]byte; _, err := io.ReadFull(peer, b[:]); read <- err }()
				if _, err := lease.Write([]byte("x")); err != nil {
					t.Errorf("retained lease write: %v", err)
				}
				if err := await(t, read); err != nil {
					t.Errorf("retained lease peer read: %v", err)
				}
			}
			if diff := gocmp.Diff(int32(258), calls.Load()); diff != "" {
				t.Errorf("shared flight dial count (-want +got):\n%s", diff)
			}
		})
	}
}
