// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

func TestHookRunnerProtocolSnapshots(t *testing.T) {
	tests := map[string]struct {
		websocket bool
		nilLast   bool
		empty     bool
	}{
		"UDP latest only": {}, "UDP empty datagram": {empty: true}, "UDP nil latest": {nilLast: true},
		"WebSocket latest and close metadata": {websocket: true}, "WebSocket nil latest": {websocket: true, nilLast: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			runner := newHookRunner(t)
			payload := []byte("latest")
			if tt.empty {
				payload = []byte{}
			}
			var f flow.Flow
			var hook addon.Hook
			if tt.websocket {
				http := flow.NewHTTPFlow(nil, nil, true)
				http.WebSocket = &websocket.Data{ClosedByClient: new(true), CloseCode: new(1000), CloseReason: new("normal"), TimestampEnd: new(float64(123))}
				for range 1024 {
					http.WebSocket.Messages = append(http.WebSocket.Messages, &websocket.Message{Content: []byte("history")})
				}
				var last *websocket.Message
				if !tt.nilLast {
					last = &websocket.Message{Type: websocket.OpBinary, FromClient: true, Content: payload}
				}
				http.WebSocket.Messages = append(http.WebSocket.Messages, last)
				f, hook = http, addon.WebSocketEndHook{Flow: http}
			} else {
				u := flow.NewUDPFlow(nil, nil, true)
				for range 1024 {
					u.Messages = append(u.Messages, &udp.Message{Content: []byte("history")})
				}
				var last *udp.Message
				if !tt.nilLast {
					last = &udp.Message{FromClient: true, Content: payload}
				}
				u.Messages = append(u.Messages, last)
				f, hook = u, addon.UDPMessageHook{Flow: u}
			}
			snapshot, err := runner.Fire(t.Context(), hook)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.NumMessages != 1025 {
				t.Fatalf("total message count = %d", snapshot.NumMessages)
			}
			if err := runner.Manager.Do(t.Context(), func(context.Context) error {
				if len(payload) > 0 {
					payload[0] = 'X'
				}
				if tt.websocket {
					d := f.(*flow.HTTPFlow).WebSocket
					*d.ClosedByClient = false
					*d.CloseCode = 1001
					*d.CloseReason = "changed"
					*d.TimestampEnd = 999
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if tt.websocket {
				want := &websocket.Data{ClosedByClient: new(true), CloseCode: new(1000), CloseReason: new("normal"), TimestampEnd: new(float64(123))}
				if !tt.nilLast {
					want.Messages = []*websocket.Message{{Type: websocket.OpBinary, FromClient: true, Content: []byte("latest")}}
				}
				if diff := gocmp.Diff(want, snapshot.WebSocket); diff != "" {
					t.Fatalf("WebSocket snapshot (-want +got):\n%s", diff)
				}
			} else {
				var want *udp.Message
				if !tt.nilLast {
					content := []byte("latest")
					if tt.empty {
						content = []byte{}
					}
					want = &udp.Message{FromClient: true, Content: content}
				}
				if diff := gocmp.Diff(want, snapshot.LastUDPMessage); diff != "" {
					t.Fatalf("UDP snapshot (-want +got):\n%s", diff)
				}
			}
		})
	}
}
