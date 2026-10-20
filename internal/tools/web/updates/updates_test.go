// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"context"
	"testing"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestWebUpdates(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"test_websocket": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			p := f.connect(t)
			do(t, f, func(ctx context.Context) error { return f.m.Options.Update(ctx, map[string]any{"anticomp": true}) })
			message := p.message(t)
			if message.Type != "options/update" {
				t.Fatalf("type = %q", message.Type)
			}
			assertJSON(t, message.Payload, map[string]any{"anticomp": map[string]any{"value": true, "choices": nil, "default": false, "help": "Try to convince servers to send us un-compressed data.", "type": "bool"}})
		}},
		"test_websocket_filter_application": {run: func(t *testing.T) {
			f := newFixture(t, nil)
			first := testflow.TFlow(testflow.WithResponse)
			first.ID = "42"
			first.Request.SetContent([]byte("foo"))
			do(t, f, func(ctx context.Context) error { f.h.cfg.View.Add(ctx, []flow.Flow{first}); return nil })
			p := f.connect(t)
			p.command(t, "search", "~bq foo")
			message := p.message(t)
			assertJSON(t, message.Payload, map[string]any{"name": "search", "matching_flow_ids": []string{"42"}})
			second := testflow.TFlow(testflow.WithResponse)
			second.ID = "41"
			second.Request.SetContent([]byte("foo\nbarbar"))
			do(t, f, func(ctx context.Context) error { f.h.cfg.View.Add(ctx, []flow.Flow{second}); return nil })
			message = p.message(t)
			if message.Type != "flows/add" {
				t.Fatalf("type = %q", message.Type)
			}
			var added struct {
				Flow struct {
					ID string `json:"id"`
				} `json:"flow"`
				Matches map[string]bool `json:"matching_filters"`
			}
			decode(t, message.Payload, &added)
			if added.Flow.ID != "41" || !added.Matches["search"] {
				t.Fatal("flow add lost identity or matching filter")
			}
			do(t, f, func(ctx context.Context) error {
				second.Request.SetContent([]byte("bar"))
				return f.h.cfg.View.Update(ctx, []flow.Flow{second})
			})
			message = p.message(t)
			decode(t, message.Payload, &added)
			if message.Type != "flows/update" || added.Flow.ID != "41" || added.Matches["search"] {
				t.Fatal("flow update retained a stale filter result")
			}
			p.command(t, "search", "")
			message = p.message(t)
			assertJSON(t, message.Payload, map[string]any{"name": "search", "matching_flow_ids": nil})
		}},
		"test_websocket_filter_command_error/missing_payload": {run: func(t *testing.T) { testBadCommand(t, `{"type":"flows/updateFilter"}`) }},
		"test_websocket_filter_command_error/unknown_command": {run: func(t *testing.T) { testBadCommand(t, `{"type":"unknownCommand"}`) }},
		"test_websocket_filter_command_error/invalid_json":    {run: func(t *testing.T) { testBadCommand(t, "invalid json") }},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}

func testBadCommand(t *testing.T, body string) {
	t.Helper()
	f := newFixture(t, nil)
	p := f.connect(t)
	if err := p.ws.WriteFrame(gows.OpcodeText, true, []byte(body), false); err != nil {
		t.Fatal(err)
	}
	assertClose(t, p, gows.CloseInternalServerErr, internalReason)
}
