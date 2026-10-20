// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"context"
	"encoding/json/jsontext"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestWebUpdateSnapshots(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"rapid_flow_changes_and_client_filters": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p, other := f.connect(t), f.connect(t)
			p.command(t, "method", "~m GET")
			_ = p.message(t)
			other.command(t, "method", "~m POST")
			_ = other.message(t)
			item := testflow.TFlow(testflow.WithResponse)
			item.ID = "same-event-identity"
			item.Request.Method = "GET"
			do(t, f, func(ctx context.Context) error {
				f.h.cfg.View.Add(ctx, []flow.Flow{item})
				item.Request.Method = "POST"
				if err := f.h.cfg.View.Update(ctx, []flow.Flow{item}); err != nil {
					return err
				}
				_, err := f.m.Call(ctx, "view.flows.remove", []flow.Flow{item})
				item.Request.Method = "DELETE"
				return err
			})
			for _, peer := range []*testPeer{p, other} {
				for index, kind := range []string{"flows/add", "flows/update", "flows/remove"} {
					message := peer.message(t)
					if message.Type != kind {
						t.Fatalf("event order = %q, want %q", message.Type, kind)
					}
					if index == 2 {
						assertJSON(t, message.Payload, item.ID)
						continue
					}
					var payload struct {
						Flow struct {
							ID      string `json:"id"`
							Request struct {
								Method string `json:"method"`
							} `json:"request"`
						} `json:"flow"`
						Matching map[string]bool `json:"matching_filters"`
					}
					decode(t, message.Payload, &payload)
					wantMethod := "GET"
					if index == 1 {
						wantMethod = "POST"
					}
					wantMatch := index == 0
					if peer == other {
						wantMatch = !wantMatch
					}
					if payload.Flow.ID != item.ID || payload.Flow.Request.Method != wantMethod || payload.Matching["method"] != wantMatch {
						t.Fatalf("event-time snapshot mismatch: event=%d method=%q match=%v", index, payload.Flow.Request.Method, payload.Matching["method"])
					}
				}
			}
		}},
		"reset_then_retained_filter_updates": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			for _, name := range []string{"first", "second"} {
				p.command(t, name, "~m GET")
				_ = p.message(t)
			}
			if _, err := f.m.Call(t.Context(), "view.clear"); err != nil {
				t.Fatal(err)
			}
			reset := p.message(t)
			if reset.Type != "flows/reset" || reset.Payload != nil {
				t.Fatal("reset must omit payload")
			}
			for _, name := range []string{"first", "second"} {
				message := p.message(t)
				if message.Type != "flows/filterUpdate" {
					t.Fatal("missing reset filter update")
				}
				assertJSON(t, message.Payload, map[string]any{"name": name, "matching_flow_ids": []string{}})
			}
		}},
		"event_ids_survive_eviction_and_clear": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			do(t, f, func(ctx context.Context) error {
				for _, msg := range []string{"first", "second", "third"} {
					if err := f.h.cfg.Events.Add(ctx, addon.LogEntry{Msg: msg}); err != nil {
						return err
					}
				}
				return nil
			})
			for index, msg := range []string{"first", "second", "third"} {
				message := p.message(t)
				if message.Type != "events/add" {
					t.Fatal("event kind changed")
				}
				assertJSON(t, message.Payload, map[string]any{"id": index + 1, "message": msg, "level": "info"})
			}
			do(t, f, func(ctx context.Context) error {
				records := f.h.cfg.Events.Records()
				if len(records) != 2 || records[0].ID != 2 || records[1].ID != 3 {
					t.Fatal("retained/stream identity mismatch")
				}
				_, err := f.m.Call(ctx, "eventstore.clear")
				if err != nil {
					return err
				}
				return f.h.cfg.Events.Add(ctx, addon.LogEntry{Msg: "fourth"})
			})
			reset := p.message(t)
			if reset.Type != "events/reset" || reset.Payload != nil {
				t.Fatal("event reset payload must be absent")
			}
			message := p.message(t)
			assertJSON(t, message.Payload, map[string]any{"id": 4, "message": "fourth", "level": "info"})
		}},
		"server_publication_omits_internal_generation": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			if err := f.h.cfg.Servers.SetupServers(t.Context()); err != nil {
				t.Fatal(err)
			}
			message := p.message(t)
			if message.Type != "state/update" {
				t.Fatalf("type=%q", message.Type)
			}
			var payload map[string]jsontext.Value
			decode(t, message.Payload, &payload)
			if len(payload) != 1 || payload["servers"] == nil {
				t.Fatal("state/update leaked internal metadata or omitted servers")
			}
			var servers map[string]jsontext.Value
			decode(t, payload["servers"], &servers)
			if len(servers) != 1 {
				t.Fatal("completed listener publication missing")
			}
			for _, raw := range servers {
				var state map[string]any
				decode(t, raw, &state)
				if state["is_running"] != true || state["last_exception"] != nil {
					t.Fatal("state/update carried an incomplete server publication")
				}
			}
			do(t, f, f.h.cfg.Servers.Done)
			message = p.message(t)
			if message.Type != "state/update" {
				t.Fatal("final server update missing")
			}
			assertJSON(t, message.Payload, map[string]any{"servers": map[string]any{}})
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}
