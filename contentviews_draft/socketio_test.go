// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/websocket"
)

func TestSocketIO(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"test_parse_packet": func(t *testing.T) {
				tests := map[string]struct {
					name    string
					payload string
				}{
					"0payload":  {"EngineIO.OPEN", "payload"},
					"40":        {"SocketIO.CONNECT", ""},
					"40payload": {"SocketIO.CONNECT", "payload"},
				}
				for input, want := range tests {
					name, payload, visible, err := parseSocketIO([]byte(input))
					if err != nil || name != want.name || string(payload) != want.payload || !visible {
						t.Errorf("parse %q = %q %q %v %v", input, name, payload, visible, err)
					}
				}
			},
			"test_view": func(t *testing.T) {
				tests := map[string]struct {
					text string
					fail bool
				}{
					"HTTP/1.1":    {fail: true},
					"GET":         {fail: true},
					"0":           {text: "EngineIO.OPEN "},
					"6":           {text: "EngineIO.NOOP "},
					"40":          {text: "SocketIO.CONNECT "},
					"4":           {fail: true},
					"42":          {text: "SocketIO.EVENT "},
					"42eventdata": {text: "SocketIO.EVENT eventdata"},
					"2":           {text: ""},
				}
				for input, want := range tests {
					text, err := (SocketIO{}).Prettify([]byte(input), contentviews.Metadata{})
					if (err != nil) != want.fail || text != want.text {
						t.Errorf("prettify %q = %q, %v; want %q, fail=%v", input, text, err, want.text, want.fail)
					}
				}
			},
			"test_render_priority": func(t *testing.T) {
				view := SocketIO{}
				if view.RenderPriority(nil, contentviews.Metadata{}) != 0 {
					t.Fatal("empty flowless packet selected")
				}
				f := &flow.HTTPFlow{Request: &httpmsg.Request{}, WebSocket: &websocket.Data{}}
				metadata := contentviews.Metadata{Flow: f}
				if view.RenderPriority(nil, metadata) != 0 || view.RenderPriority([]byte("message"), metadata) != 0 {
					t.Fatal("packet selected without Socket.IO path")
				}
				f.Request.Path = "/asdf/socket.io/?..."
				if view.RenderPriority([]byte("message"), metadata) != 1 || view.RenderPriority(nil, metadata) != 0 {
					t.Fatal("Socket.IO path selection mismatch")
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
}

func TestSocketIOAdditional(t *testing.T) {
	tests := map[string]struct {
		data string
		want string
	}{
		"pong hidden":       {"3payload", ""},
		"ack hidden":        {"43payload", ""},
		"binary ack hidden": {"46payload", ""},
		"escaped payload":   {"42\x00\n'", "SocketIO.EVENT \\x00\\n'"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := (SocketIO{}).Prettify([]byte(tt.data), contentviews.Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	budget := &viewBudget{view: "Socket.IO", bytes: maxViewBytes - 3}
	if _, err := escapedViewBytes([]byte{0}, budget); err == nil {
		t.Fatal("escaped expansion bypassed remaining output budget")
	} else if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("expected typed output limit, got %v", err)
	}
}

func FuzzSocketIO(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("0payload"), []byte("40"), []byte("42eventdata"), []byte("HTTP/1.1"), {0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		text, err := (SocketIO{}).Prettify(data, contentviews.Metadata{})
		if err == nil && len(text) > maxViewBytes {
			t.Fatal("output exceeds resource bound")
		}
	})
}
