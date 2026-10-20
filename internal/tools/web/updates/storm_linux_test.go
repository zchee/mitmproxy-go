//go:build webstorm && linux

// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestWebUpdateStorm(t *testing.T) {
	tests := map[string]struct{}{"nonreader_peer_close": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			configured := make(chan error, 1)
			f := newFixture(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("X-Test-Nonreader") != "yes" {
						next.ServeHTTP(w, r)
						return
					}
					next.ServeHTTP(hijackWriter{ResponseWriter: w, wrap: func(conn net.Conn) net.Conn {
						tcp, ok := conn.(*net.TCPConn)
						if !ok {
							configured <- errors.New("storm requires TCP")
							_ = conn.Close()
							return conn
						}
						configured <- tcp.SetWriteBuffer(1024)
						return conn
					}}, r)
				})
			})
			slow, status := f.open(t, http.Header{"Authorization": {"Bearer " + fixturePassword}, "X-Test-Nonreader": {"yes"}}, nil)
			if status != 101 {
				t.Fatal("nonreader upgrade failed")
			}
			if err := await(t, configured); err != nil {
				t.Fatal(err)
			}
			if err := slow.conn.(*net.TCPConn).SetReadBuffer(1024); err != nil {
				t.Fatal(err)
			}
			slow.command(t, "ready", "")
			if slow.message(t).Type != "flows/filterUpdate" {
				t.Fatal("nonreader admission barrier failed")
			}
			c := onlyClient(t, f)
			c.mu.Lock()
			before := c.started
			c.mu.Unlock()
			peers := []*testPeer{f.connect(t), f.connect(t)}
			type result struct {
				count int
				err   error
			}
			readers := make(chan result, len(peers))
			for _, peer := range peers {
				go func() {
					for index := range 10000 {
						if err := peer.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
							readers <- result{index, err}
							return
						}
						frame, err := peer.ws.ReadFrame()
						if err != nil {
							readers <- result{index, err}
							return
						}
						if frame.Header.Opcode != gows.OpcodeText || !frame.Header.Fin {
							readers <- result{index, errors.New("reading peer lost ordinary stream")}
							return
						}
						var envelope struct {
							Type    string `json:"type"`
							Payload struct {
								Flow struct {
									ID      string `json:"id"`
									Request struct {
										Method string `json:"method"`
									} `json:"request"`
								} `json:"flow"`
								Matching map[string]bool `json:"matching_filters"`
							} `json:"payload"`
						}
						if err := json.Unmarshal(frame.Payload, &envelope); err != nil {
							readers <- result{index, err}
							return
						}
						if envelope.Type != "flows/add" || envelope.Payload.Flow.ID != flowID(index) || envelope.Payload.Flow.Request.Method != "GET" || envelope.Payload.Matching == nil || len(envelope.Payload.Matching) != 0 {
							readers <- result{index, errors.New("reading peer observed unordered or incoherent flow")}
							return
						}
					}
					readers <- result{count: 10000}
				}()
			}
			start := time.Now()
			do(t, f, func(ctx context.Context) error {
				for index := range 10000 {
					item := testflow.TFlow()
					item.ID = flowID(index)
					item.Request.Method = "GET"
					if err := f.m.Addons.Trigger(ctx, addon.RequestHeadersHook{Flow: item}); err != nil {
						return err
					}
				}
				return nil
			})
			produced := time.Now()
			if produced.Sub(start) >= 10*time.Second {
				t.Fatalf("10000 hook additions took%v", produced.Sub(start))
			}
			c.mu.Lock()
			terminal, decision, high, claimed := c.terminal, c.terminalAt, c.highWater, c.terminalStarted
			c.mu.Unlock()
			if !terminal || high != queueCapacity || claimed <= before {
				t.Fatalf("controlled queue overflow not observed:terminal=%v high=%d claimed=%d", terminal, high, claimed)
			}
			resume := time.Now()
			if resume.Sub(decision) >= terminalGrace {
				t.Fatal("nonreader resumed after terminal grace")
			}
			count := 0
			var peerClose gows.CloseError
			for {
				frame := slow.frame(t)
				if frame.Header.Opcode == gows.OpcodeClose {
					var err error
					peerClose, err = gows.ParseClose(frame.Payload)
					if err != nil {
						t.Fatal(err)
					}
					_ = slow.ws.WriteFrame(gows.OpcodeClose, true, frame.Payload, false)
					break
				}
				if frame.Header.Opcode != gows.OpcodeText || !frame.Header.Fin {
					t.Fatal("nonreader received invalid in-flight frame")
				}
				var envelope struct {
					Type    string `json:"type"`
					Payload struct {
						Flow struct {
							ID string `json:"id"`
						} `json:"flow"`
					} `json:"payload"`
				}
				decode(t, frame.Payload, &envelope)
				if envelope.Type != "flows/add" || envelope.Payload.Flow.ID != flowID(count) {
					t.Fatal("nonreader received out-of-order backlog")
				}
				count++
			}
			closed := time.Now()
			if peerClose.Code != gows.CloseInternalServerErr || peerClose.Reason != internalReason {
				t.Fatalf("peer parsed code%d,not1011", peerClose.Code)
			}
			if uint64(count) != claimed-before {
				t.Fatalf("ordinary frames after terminal selection:peer%d claimed%d", count, claimed-before)
			}
			await(t, c.done)
			c.mu.Lock()
			outcome, sent := c.outcome, c.sent
			c.mu.Unlock()
			if outcome != "close-exchanged" || sent != claimed || closed.Sub(decision) >= terminalGrace {
				t.Fatalf("overflow did not finish gracefully:outcome=%s sent=%d claimed=%d", outcome, sent, claimed)
			}
			for range peers {
				result := await(t, readers)
				if result.err != nil || result.count != 10000 {
					t.Fatalf("reader count=%d error=%v", result.count, result.err)
				}
			}
			metrics := map[string]any{"produced": 10000, "readers": len(peers), "production_ns": produced.Sub(start).Nanoseconds(), "terminal_ns": decision.Sub(start).Nanoseconds(), "resume_ns": resume.Sub(start).Nanoseconds(), "close_ns": closed.Sub(start).Nanoseconds(), "queue_high_water": high, "local_intent": 1011, "peer_code": int(peerClose.Code), "outcome": outcome, "joined": true, "nonreader_data_frames": count}
			encoded, err := json.Marshal(metrics)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("webstorm metrics %s", encoded)
		})
	}
}
