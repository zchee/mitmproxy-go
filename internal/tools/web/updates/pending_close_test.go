// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"
)

func testUpgradeClose(t *testing.T) {
	tests := map[string]struct{ doneFirst bool }{
		"close_interrupts_pending_handshake":           {},
		"done_then_close_interrupts_pending_handshake": {doneFirst: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			accepted := make(chan *gatedConn, 1)
			f := newFixture(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(hijackWriter{ResponseWriter: w, wrap: func(conn net.Conn) net.Conn {
						gate := &gatedConn{Conn: conn, entered: make(chan struct{}), release: make(chan struct{}), stopped: make(chan struct{})}
						gate.armed.Store(true)
						accepted <- gate
						return gate
					}}, r)
				})
			})
			admitted := make(chan *client, 1)
			f.h.afterAdmission = func() {
				_ = f.m.Do(t.Context(), func(context.Context) error {
					for c := range f.h.clients {
						admitted <- c
					}
					return nil
				})
			}
			dialed := make(chan error, 1)
			go func() {
				dialer := gows.Dialer{HTTPHeader: http.Header{"Authorization": {"Bearer " + fixturePassword}}}
				conn, hs, err := dialer.Dial(t.Context(), "ws"+strings.TrimPrefix(f.server.URL, "http")+"/updates")
				if err == nil {
					hs.Release()
					_ = conn.Close()
				}
				dialed <- err
			}()
			c, gate := await(t, admitted), await(t, accepted)
			t.Cleanup(func() { close(gate.release) })
			await(t, gate.entered)
			c.mu.Lock()
			pending := c.pending != nil && c.ws == nil
			c.mu.Unlock()
			if !pending {
				t.Fatal("blocked 101 transport is not owned by the admitted client")
			}
			if tt.doneFirst {
				done := make(chan error, 1)
				go func() { done <- f.m.Do(t.Context(), f.h.Done) }()
				if err := await(t, done); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			closed := make(chan error, 1)
			go func() { closed <- f.h.Close(ctx) }()
			if err := await(t, closed); !errors.Is(err, context.Canceled) {
				t.Fatalf("Close during pending upgrade = %v, want context.Canceled", err)
			}
			if err := await(t, dialed); err == nil {
				t.Fatal("pending handshake succeeded after Close")
			}
			await(t, c.done)
			c.mu.Lock()
			finished, attached, pending, outcome := c.finished, c.ws != nil, c.pending != nil, c.outcome
			closeFrame, err := gows.ParseClose(c.closeBody)
			c.mu.Unlock()
			if !finished || attached || pending || err != nil || closeFrame.Code != gows.CloseGoingAway {
				t.Fatalf("closed pending client: finished=%v attached=%v pending=%v close=%v error=%v", finished, attached, pending, closeFrame.Code, err)
			}
			if diff := gocmp.Diff("transport-aborted", outcome); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(int32(1), gate.closes.Load()); diff != "" {
				t.Fatal(diff)
			}
			do(t, f, func(context.Context) error {
				if diff := gocmp.Diff(0, len(f.h.clients)); diff != "" {
					t.Fatal(diff)
				}
				return nil
			})
			if err := f.h.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
