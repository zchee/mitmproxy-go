// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func testAdmission(t *testing.T) {
	tests := map[string]struct {
		reject bool
		abort  bool
		before func(*testing.T, *streamFixture, *client)
		after  func(*testing.T, *streamFixture, *client, *testPeer)
	}{
		"queued_flow_precedes_later_events": {
			before: func(t *testing.T, f *streamFixture, c *client) {
				item := testflow.TFlow()
				item.ID = "before-handshake"
				do(t, f, func(ctx context.Context) error { f.h.cfg.View.Add(ctx, []flow.Flow{item}); return nil })
				c.mu.Lock()
				queued, started := len(c.queue), c.started
				c.mu.Unlock()
				if queued != 1 || started != 0 {
					t.Fatalf("pending queue=%d started=%d, want 1 and 0", queued, started)
				}
			},
			after: func(t *testing.T, f *streamFixture, c *client, p *testPeer) {
				item := testflow.TFlow()
				item.ID = "after-handshake"
				do(t, f, func(ctx context.Context) error { f.h.cfg.View.Add(ctx, []flow.Flow{item}); return nil })
				var kinds, ids []string
				for range 2 {
					message := p.message(t)
					var payload struct {
						Flow struct {
							ID string `json:"id"`
						} `json:"flow"`
					}
					decode(t, message.Payload, &payload)
					kinds = append(kinds, message.Type)
					ids = append(ids, payload.Flow.ID)
				}
				if diff := gocmp.Diff([]string{"flows/add", "flows/add"}, kinds); diff != "" {
					t.Fatal(diff)
				}
				if diff := gocmp.Diff([]string{"before-handshake", "after-handshake"}, ids); diff != "" {
					t.Fatal(diff)
				}
				if err := p.ws.WriteFrame(gows.OpcodeClose, true, nil, false); err != nil {
					t.Fatal(err)
				}
				if frame := p.frame(t); frame.Header.Opcode != gows.OpcodeClose {
					t.Fatal("close exchange did not follow the queued events")
				}
				await(t, c.done)
			},
		},
		"upgrade_failure_discards_admitted_client": {
			reject: true,
			before: func(t *testing.T, f *streamFixture, _ *client) {
				do(t, f, func(ctx context.Context) error { return f.h.cfg.Events.Add(ctx, addon.LogEntry{Msg: "pending"}) })
			},
			after: func(t *testing.T, f *streamFixture, c *client, _ *testPeer) {
				await(t, c.done)
				c.mu.Lock()
				terminal, ws, outcome := c.terminal, c.ws, c.outcome
				c.mu.Unlock()
				if terminal || ws != nil || outcome != "" {
					t.Fatalf("failed upgrade selected terminal=%v transport=%v outcome=%q", terminal, ws != nil, outcome)
				}
				if err := f.h.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
			},
		},
		"overflow_before_attachment_retains_peer_1011": {
			before: func(t *testing.T, f *streamFixture, c *client) {
				do(t, f, func(ctx context.Context) error {
					for range queueCapacity + 1 {
						if err := f.h.cfg.Events.Add(ctx, addon.LogEntry{Msg: "pending"}); err != nil {
							return err
						}
					}
					return nil
				})
				c.mu.Lock()
				terminal, high, started := c.terminal, c.highWater, c.started
				c.mu.Unlock()
				if !terminal || high != queueCapacity || started != 0 {
					t.Fatalf("pending overflow: terminal=%v high-water=%d started=%d", terminal, high, started)
				}
			},
			after: func(t *testing.T, _ *streamFixture, c *client, p *testPeer) {
				assertClose(t, p, gows.CloseInternalServerErr, internalReason)
				await(t, c.done)
				c.mu.Lock()
				outcome := c.outcome
				c.mu.Unlock()
				if diff := gocmp.Diff("close-exchanged", outcome); diff != "" {
					t.Fatal(diff)
				}
			},
		},
		"done_before_attachment_sends_going_away": {
			before: func(t *testing.T, f *streamFixture, _ *client) { do(t, f, f.h.Done) },
			after: func(t *testing.T, _ *streamFixture, c *client, p *testPeer) {
				assertClose(t, p, gows.CloseGoingAway, "Going away.")
				await(t, c.done)
			},
		},
		"abort_before_attachment_cannot_resurrect_client": {
			abort:  true,
			before: func(_ *testing.T, _ *streamFixture, c *client) { c.abort() },
			after: func(t *testing.T, f *streamFixture, c *client, _ *testPeer) {
				await(t, c.done)
				c.mu.Lock()
				finished, ws, pending, outcome := c.finished, c.ws, c.pending, c.outcome
				c.mu.Unlock()
				if !finished || ws != nil || pending != nil {
					t.Fatal("transport attachment resurrected an aborted client")
				}
				if diff := gocmp.Diff("transport-aborted", outcome); diff != "" {
					t.Fatal(diff)
				}
				if err := f.h.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if tt.reject {
						w.Header().Set("Sec-WebSocket-Protocol", "reject-pending-header")
					}
					next.ServeHTTP(w, r)
				})
			})
			admitted, release := make(chan *client, 1), make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			f.h.afterAdmission = func() {
				var c *client
				_ = f.m.Do(t.Context(), func(context.Context) error {
					for registered := range f.h.clients {
						c = registered
					}
					return nil
				})
				admitted <- c
				<-release
			}
			type dialResult struct {
				conn net.Conn
				hs   gows.Handshake
				err  error
			}
			result := make(chan dialResult, 1)
			go func() {
				dialer := gows.Dialer{HTTPHeader: http.Header{"Authorization": {"Bearer " + fixturePassword}}}
				conn, hs, err := dialer.Dial(t.Context(), "ws"+strings.TrimPrefix(f.server.URL, "http")+"/updates")
				result <- dialResult{conn: conn, hs: hs, err: err}
			}()
			c := await(t, admitted)
			if c == nil {
				t.Fatal("upgrade began before dispatch admitted the client")
			}
			c.mu.Lock()
			pending := c.ws == nil
			c.mu.Unlock()
			if !pending {
				t.Fatal("transport attached before the handshake barrier")
			}
			tt.before(t, f, c)
			close(release)
			dial := await(t, result)
			var p *testPeer
			if tt.reject || tt.abort {
				if dial.err == nil {
					_ = dial.conn.Close()
					t.Fatal("rejected or aborted pending client upgraded successfully")
				}
				if tt.abort && !errors.Is(dial.err, io.EOF) && !errors.Is(dial.err, io.ErrUnexpectedEOF) && !errors.Is(dial.err, net.ErrClosed) {
					t.Fatalf("pending abort dial error = %v, want a closed-connection error", dial.err)
				}
			} else {
				if dial.err != nil {
					t.Fatal(dial.err)
				}
				p = &testPeer{conn: dial.conn, ws: gows.NewClientConn(dial.conn, gows.WithBuffered(dial.hs.Buffered))}
				dial.hs.Release()
				t.Cleanup(func() { _ = p.ws.Abort() })
				if err := p.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			tt.after(t, f, c, p)
			do(t, f, func(context.Context) error {
				if diff := gocmp.Diff(0, len(f.h.clients)); diff != "" {
					t.Fatal(diff)
				}
				return nil
			})
		})
	}
}
