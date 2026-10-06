// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
)

type websocketUpgradeObserver struct {
	calls    []string
	messages map[bool]string
	flow     *flow.HTTPFlow
}

func (a *websocketUpgradeObserver) WebSocketStart(_ context.Context, f *flow.HTTPFlow) error {
	a.flow = f
	a.messages = make(map[bool]string)
	a.calls = append(a.calls, "websocket_start")
	return nil
}

func (a *websocketUpgradeObserver) WebSocketMessage(_ context.Context, f *flow.HTTPFlow) error {
	a.calls = append(a.calls, "websocket_message")
	message := f.WebSocket.Messages[len(f.WebSocket.Messages)-1]
	a.messages[message.FromClient] += string(message.Content)
	return nil
}

func (a *websocketUpgradeObserver) WebSocketEnd(_ context.Context, _ *flow.HTTPFlow) error {
	a.calls = append(a.calls, "websocket_end")
	return nil
}

func TestLayerWebSocketUpgradeBufferedFrames(t *testing.T) {
	tests := map[string]struct{ raw bool }{"success: framed upgrade with raw fallback enabled": {raw: true}, "success: framed upgrade without raw fallback": {}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			raw := "rawtcp=false"
			if tt.raw {
				raw = "rawtcp=true"
			}
			s := newLayerSession(t, nil, "connection_strategy=lazy", "websocket=true", raw)
			observer := &websocketUpgradeObserver{}
			if err := s.m.Do(t.Context(), func(ctx context.Context) error { return s.m.Addons.Add(ctx, observer) }); err != nil {
				t.Fatal(err)
			}
			s.start(hookdata.HTTPModeRegular)
			request := "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
			// RFC 6455 permits any masking key, including this zero key. The frame
			// is coalesced with the HTTP head to exercise unread-byte ownership.
			clientFrame := append([]byte{0x81, 0x8f, 0, 0, 0, 0}, []byte("client greeting")...)
			write(t, s.client, request+string(clientFrame))
			origin := await(t, s.pool.origins)
			expectRead(t, origin, "GET / HTTP/1.1\r\nHost: origin.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
			response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
			serverFrame := append([]byte{0x81, 15}, []byte("server greeting")...)
			write(t, origin, response+string(serverFrame))
			expectRead(t, s.client, response)
			client, server := gows.NewClientConn(s.client), gows.NewServerConn(origin)
			frame, err := client.ReadFrame()
			if err != nil || string(frame.Payload) != "server greeting" {
				t.Fatalf("buffered server frame = %+v, %v", frame, err)
			}
			frame, err = server.ReadFrame()
			if err != nil || string(frame.Payload) != "client greeting" {
				t.Fatalf("buffered client frame = %+v, %v", frame, err)
			}
			if err := client.WriteFrame(gows.OpcodeBinary, true, []byte("later client"), false); err != nil {
				t.Fatal(err)
			}
			frame, err = server.ReadFrame()
			if err != nil || string(frame.Payload) != "later client" {
				t.Fatalf("later client frame = %+v, %v", frame, err)
			}
			if err := server.WriteFrame(gows.OpcodeBinary, true, []byte("later server"), false); err != nil {
				t.Fatal(err)
			}
			frame, err = client.ReadFrame()
			if err != nil || string(frame.Payload) != "later server" {
				t.Fatalf("later server frame = %+v, %v", frame, err)
			}
			if err := client.WriteFrame(gows.OpcodeClose, true, []byte{0x03, 0xe8}, false); err != nil {
				t.Fatal(err)
			}
			frame, err = server.ReadFrame()
			if err != nil || frame.Header.Opcode != gows.OpcodeClose {
				t.Fatalf("forwarded close = %+v, %v", frame, err)
			}
			if err := server.WriteFrame(gows.OpcodeClose, true, frame.Payload, false); err != nil {
				t.Fatal(err)
			}
			frame, err = client.ReadFrame()
			if err != nil || frame.Header.Opcode != gows.OpcodeClose {
				t.Fatalf("close reply = %+v, %v", frame, err)
			}
			if err := await(t, s.done); err != nil {
				t.Fatal(err)
			}
			if err := s.m.Do(t.Context(), func(context.Context) error {
				want := []string{"websocket_start", "websocket_message", "websocket_message", "websocket_message", "websocket_message", "websocket_end"}
				if diff := gocmp.Diff(want, observer.calls); diff != "" {
					t.Errorf("upgrade lifecycle (-want +got):\n%s", diff)
				}
				if diff := gocmp.Diff(map[bool]string{true: "client greetinglater client", false: "server greetinglater server"}, observer.messages); diff != "" {
					t.Errorf("upgrade messages (-want +got):\n%s", diff)
				}
				if observer.flow == nil || observer.flow.Live || observer.flow.WebSocket == nil {
					t.Error("WebSocket lifetime did not finish on the original HTTP flow")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
