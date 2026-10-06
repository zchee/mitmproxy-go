// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dumper

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// TestProtocolPresentation compares full dispatched output with text measured
// from the pinned Python dumper, including datagram/message boundaries and
// different HTTP versions on the two sides of an exchange.
func TestProtocolPresentation(t *testing.T) {
	tests := map[string]struct {
		hook   func() addon.Hook
		detail int
		want   string
	}{
		"udp server summary": {
			hook:   func() addon.Hook { return addon.UDPMessageHook{Flow: testflow.TUDPFlow()} },
			detail: 1,
			want:   "127.0.0.1:22 <- udp <- address:22\n",
		},
		"udp client content": {
			hook: func() addon.Hook {
				f := testflow.TUDPFlow()
				f.Messages = f.Messages[:1]
				return addon.UDPMessageHook{Flow: f}
			},
			detail: 3,
			want:   "127.0.0.1:22 -> udp -> address:22\n\n    hello\n\n",
		},
		"udp empty datagram": {
			hook: func() addon.Hook {
				f := testflow.TUDPFlow()
				f.Messages[len(f.Messages)-1].Content = []byte{}
				return addon.UDPMessageHook{Flow: f}
			},
			detail: 3,
			want:   "127.0.0.1:22 <- udp <- address:22\n\n",
		},
		"udp error": {
			hook:   func() addon.Hook { return addon.UDPErrorHook{Flow: testflow.TUDPFlow(testflow.WithError)} },
			detail: 3,
			want:   "Error in UDP connection to address:22: error\n",
		},
		"websocket server text": {
			hook:   func() addon.Hook { return addon.WebSocketMessageHook{Flow: testflow.TWebSocketFlow()} },
			detail: 3,
			want:   "127.0.0.1:22 <- WebSocket text message <- address:22/ws\n\n    it's me\n\n",
		},
		"websocket client binary": {
			hook: func() addon.Hook {
				f := testflow.TWebSocketFlow()
				f.WebSocket.Messages = f.WebSocket.Messages[:1]
				return addon.WebSocketMessageHook{Flow: f}
			},
			detail: 1,
			want:   "127.0.0.1:22 -> WebSocket binary message -> address:22/ws\n",
		},
		"websocket empty message": {
			hook: func() addon.Hook {
				f := testflow.TWebSocketFlow()
				f.WebSocket.Messages[len(f.WebSocket.Messages)-1].Content = []byte{}
				return addon.WebSocketMessageHook{Flow: f}
			},
			detail: 3,
			want:   "127.0.0.1:22 <- WebSocket text message <- address:22/ws\n\n",
		},
		"websocket absent close status": {
			hook: func() addon.Hook {
				f := testflow.TWebSocketFlow()
				f.WebSocket.CloseCode = new(1005)
				return addon.WebSocketEndHook{Flow: f}
			},
			detail: 1,
			want:   "WebSocket connection closed by server: 1005 \n",
		},
		"websocket client close": {
			hook: func() addon.Hook {
				f := testflow.TWebSocketFlow()
				f.WebSocket.ClosedByClient = new(true)
				f.WebSocket.CloseReason = new("done")
				return addon.WebSocketEndHook{Flow: f}
			},
			detail: 1,
			want:   "WebSocket connection closed by client: 1000 done\n",
		},
		"websocket abnormal close": {
			hook:   func() addon.Hook { return addon.WebSocketEndHook{Flow: testflow.TWebSocketFlow(testflow.WithError)} },
			detail: 1,
			want:   "Error in WebSocket connection to address:22: WebSocket Error: ABNORMAL_CLOSURE\n",
		},
		"http2 matching versions": {
			hook: func() addon.Hook {
				f := testflow.TFlow(testflow.WithResponse)
				f.Request.HTTPVersion = "HTTP/2.0"
				f.Response.HTTPVersion = "HTTP/2.0"
				f.Response.Reason = "ignored"
				return addon.ResponseHook{Flow: f}
			},
			detail: 1,
			want:   "127.0.0.1:22: GET http://address:22/path HTTP/2.0\n  << HTTP/2.0 200 OK 7b\n",
		},
		"http2 to http1": {
			hook: func() addon.Hook {
				f := testflow.TFlow(testflow.WithResponse)
				f.Request.HTTPVersion = "HTTP/2.0"
				return addon.ResponseHook{Flow: f}
			},
			detail: 1,
			want:   "127.0.0.1:22: GET http://address:22/path HTTP/2.0\n  << HTTP/1.1 200 OK 7b\n",
		},
		"http1 to http2": {
			hook: func() addon.Hook {
				f := testflow.TFlow(testflow.WithResponse)
				f.Response.HTTPVersion = "HTTP/2.0"
				f.Response.Reason = "ignored"
				return addon.ResponseHook{Flow: f}
			},
			detail: 1,
			want:   "127.0.0.1:22: GET http://address:22/path HTTP/1.1\n  << HTTP/2.0 200 OK 7b\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, manager, out := setup(t)
			if err := configure(t, manager, map[string]any{"flow_detail": tt.detail}); err != nil {
				t.Fatal(err)
			}
			if err := manager.Hook(t.Context(), tt.hook()); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, out.String()); diff != "" {
				t.Fatalf("dispatched presentation (-upstream +go):\n%s", diff)
			}
		})
	}
}
