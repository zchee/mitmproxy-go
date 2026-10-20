// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// Only the connection's real write boundary is gated; protocol peers and HTTP
// handling remain real. Close interrupts the gate just as it interrupts the I/O.
type gatedConn struct {
	net.Conn
	armed     atomic.Bool
	partial   bool
	entered   chan struct{}
	release   chan struct{}
	stopped   chan struct{}
	gate      sync.Once
	closeOnce sync.Once
	closes    atomic.Int32
}

func (c *gatedConn) Write(body []byte) (int, error) {
	var gated bool
	if c.armed.Load() {
		c.gate.Do(func() { gated = true })
	}
	if !gated {
		return c.Conn.Write(body)
	}
	written := 0
	if c.partial && len(body) > 0 {
		n, err := c.Conn.Write(body[:1])
		written = n
		if err != nil {
			return n, err
		}
	}
	close(c.entered)
	select {
	case <-c.release:
		n, err := c.Conn.Write(body[written:])
		return n + written, err
	case <-c.stopped:
		return written, net.ErrClosed
	}
}

func (c *gatedConn) Close() error {
	c.closeOnce.Do(func() { c.closes.Add(1); close(c.stopped); _ = c.Conn.Close() })
	return nil
}

func TestWebUpdateOverflow(t *testing.T) {
	tests := map[string]struct{ partial bool }{"graceful_peer_close": {}, "blocked_partial_write_abort": {partial: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			accepted := make(chan *gatedConn, 1)
			f := newFixture(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(hijackWriter{ResponseWriter: w, wrap: func(conn net.Conn) net.Conn {
						g := &gatedConn{Conn: conn, partial: tt.partial, entered: make(chan struct{}), release: make(chan struct{}), stopped: make(chan struct{})}
						accepted <- g
						return g
					}}, r)
				})
			})
			p := f.connect(t)
			gate := await(t, accepted)
			c := onlyClient(t, f)
			gate.armed.Store(true)
			item := testflow.TFlow()
			item.ID = "in-flight"
			if err := f.m.Addons.Trigger(t.Context(), addon.RequestHeadersHook{Flow: item}); err != nil {
				t.Fatal(err)
			}
			await(t, gate.entered)
			do(t, f, func(ctx context.Context) error {
				for index := range queueCapacity + 1 {
					next := testflow.TFlow()
					next.ID = flowID(index)
					if err := f.m.Addons.Trigger(ctx, addon.RequestHeadersHook{Flow: next}); err != nil {
						return err
					}
				}
				return nil
			})
			c.mu.Lock()
			terminal, at, high := c.terminal, c.terminalAt, c.highWater
			c.mu.Unlock()
			if !terminal || high != queueCapacity {
				t.Fatalf("overflow not reached:terminal=%v high-water=%d", terminal, high)
			}
			if tt.partial {
				await(t, c.done)
				elapsed := time.Since(at)
				if elapsed < terminalGrace || elapsed > terminalGrace+5*time.Second {
					t.Fatalf("Abort/join bound=%v,want15s grace plus bounded scheduling", elapsed)
				}
				c.mu.Lock()
				outcome := c.outcome
				c.mu.Unlock()
				if outcome != "transport-aborted" {
					t.Fatalf("partial-write outcome=%q; cannot claim peer Close", outcome)
				}
			} else {
				close(gate.release)
				message := p.message(t)
				if message.Type != "flows/add" {
					t.Fatal("in-flight frame was invalidated")
				}
				var payload struct {
					Flow struct {
						ID string `json:"id"`
					} `json:"flow"`
				}
				decode(t, message.Payload, &payload)
				if payload.Flow.ID != "in-flight" {
					t.Fatal("queued backlog preceded terminal Close")
				}
				assertClose(t, p, gows.CloseInternalServerErr, internalReason)
				await(t, c.done)
				if time.Since(at) >= terminalGrace {
					t.Fatal("peer Close came after terminal grace")
				}
				c.mu.Lock()
				outcome := c.outcome
				c.mu.Unlock()
				if outcome != "close-exchanged" {
					t.Fatalf("graceful outcome=%q", outcome)
				}
			}
			if gate.closes.Load() != 1 {
				t.Fatalf("owned connection closes=%d,want1", gate.closes.Load())
			}
			do(t, f, func(context.Context) error {
				if len(f.h.clients) != 0 {
					t.Fatal("terminal client remained registered")
				}
				return nil
			})
		})
	}
}
