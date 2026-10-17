// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package contentviews

import (
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/websocket"
)

func TestSocketIODifferential(t *testing.T) {
	output := difftest.Python(t, `
import json
from mitmproxy.contentviews import Metadata
from mitmproxy.contentviews._view_socketio import parse_packet, socket_io
from mitmproxy.test import tflow

result = {"parse": [], "view": [], "priority": []}
for data in [b"0payload", b"40", b"40payload"]:
    kind, payload = parse_packet(data)
    result["parse"].append(str(kind) + "|" + payload.decode())
for data in [b"HTTP/1.1", b"GET", b"0", b"6", b"40", b"4", b"42", b"42eventdata", b"2"]:
    try:
        result["view"].append(socket_io.prettify(data, Metadata()))
    except Exception:
        result["view"].append("[error]")
result["priority"].append(socket_io.render_priority(b"", Metadata()))
flow = tflow.twebsocketflow()
result["priority"].append(socket_io.render_priority(b"", Metadata(flow=flow)))
result["priority"].append(socket_io.render_priority(b"message", Metadata(flow=flow)))
flow.request.path = "/asdf/socket.io/?..."
result["priority"].append(socket_io.render_priority(b"message", Metadata(flow=flow)))
result["priority"].append(socket_io.render_priority(b"", Metadata(flow=flow)))
print(json.dumps(result))
`, nil)
	var reference struct {
		Parse    []string  `json:"parse"`
		View     []string  `json:"view"`
		Priority []float64 `json:"priority"`
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"test_parse_packet": func(t *testing.T) {
				var got []string
				for _, input := range []string{"0payload", "40", "40payload"} {
					name, data, _, err := parseSocketIO([]byte(input))
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, name+"|"+string(data))
				}
				if diff := cmp.Diff(reference.Parse, got); diff != "" {
					t.Fatal(diff)
				}
			},
			"test_view": func(t *testing.T) {
				var got []string
				for _, input := range []string{"HTTP/1.1", "GET", "0", "6", "40", "4", "42", "42eventdata", "2"} {
					text, err := (SocketIO{}).Prettify([]byte(input), Metadata{})
					if err != nil {
						text = "[error]"
					}
					got = append(got, text)
				}
				if diff := cmp.Diff(reference.View, got); diff != "" {
					t.Fatal(diff)
				}
			},
			"test_render_priority": func(t *testing.T) {
				view := SocketIO{}
				got := []float64{view.RenderPriority(nil, Metadata{})}
				f := &flow.HTTPFlow{Request: &httpmsg.Request{}, WebSocket: &websocket.Data{}}
				metadata := Metadata{Flow: f}
				got = append(got, view.RenderPriority(nil, metadata), view.RenderPriority([]byte("message"), metadata))
				f.Request.Path = "/asdf/socket.io/?..."
				got = append(got, view.RenderPriority([]byte("message"), metadata), view.RenderPriority(nil, metadata))
				if diff := cmp.Diff(reference.Priority, got); diff != "" {
					t.Fatal(diff)
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}
