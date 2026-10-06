// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"net"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

func TestHandlerProtocolInjectionValidation(t *testing.T) {
	tests := map[string]struct {
		protocol  string
		message   any
		direction layer.InjectionDirection
		wrongID   bool
		want      error
	}{
		"UDP empty packet":               {protocol: "udp", message: &udp.Message{}},
		"UDP maximum":                    {protocol: "udp", message: &udp.Message{Content: make([]byte, layer.MaxUDPPacketBytes)}},
		"UDP oversized":                  {protocol: "udp", message: &udp.Message{Content: make([]byte, layer.MaxUDPPacketBytes+1)}, want: ErrInjectionSize},
		"UDP wrong type":                 {protocol: "udp", message: &tcp.Message{}, want: ErrInjectionType},
		"UDP typed nil":                  {protocol: "udp", message: (*udp.Message)(nil), want: ErrInjectionType},
		"UDP identity mismatch":          {protocol: "udp", message: &udp.Message{}, wrongID: true, want: ErrInjectionIdentity},
		"UDP direction mismatch":         {protocol: "udp", message: &udp.Message{}, direction: layer.DirectionFromClient, want: ErrInjectionDirection},
		"UDP invalid direction":          {protocol: "udp", message: &udp.Message{}, direction: 255, want: ErrInjectionDirection},
		"WebSocket text":                 {protocol: "websocket", message: &websocket.Message{Type: websocket.OpText, FromClient: true}, direction: layer.DirectionFromClient},
		"WebSocket binary":               {protocol: "websocket", message: &websocket.Message{Type: websocket.OpBinary}, direction: layer.DirectionFromServer},
		"WebSocket oversized":            {protocol: "websocket", message: &websocket.Message{Type: websocket.OpBinary, Content: make([]byte, layer.MaxInjectionBytes+1)}, want: ErrInjectionSize},
		"WebSocket control frame":        {protocol: "websocket", message: &websocket.Message{Type: websocket.OpPing}, want: ErrInjectionType},
		"WebSocket continuation":         {protocol: "websocket", message: &websocket.Message{Type: websocket.OpContinuation}, want: ErrInjectionType},
		"WebSocket wrong type":           {protocol: "websocket", message: &udp.Message{}, want: ErrInjectionType},
		"WebSocket typed nil":            {protocol: "websocket", message: (*websocket.Message)(nil), want: ErrInjectionType},
		"WebSocket identity mismatch":    {protocol: "websocket", message: &websocket.Message{Type: websocket.OpText}, wrongID: true, want: ErrInjectionIdentity},
		"WebSocket direction mismatch":   {protocol: "websocket", message: &websocket.Message{Type: websocket.OpText}, direction: layer.DirectionFromClient, want: ErrInjectionDirection},
		"HTTP without upgrade unchanged": {protocol: "http", message: &websocket.Message{Type: websocket.OpText}, want: ErrInjectionType},
		"TCP unchanged":                  {protocol: "tcp", message: &tcp.Message{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := startHandler(t, func(ctx context.Context, _ *layer.Context) error { <-ctx.Done(); return ctx.Err() })
			defer func() { fixture.connections.Close(); _ = await(t, fixture.done) }()
			client := &connection.Client{ID: fixture.id(t)}
			var live flow.Flow
			switch tt.protocol {
			case "udp":
				live = flow.NewUDPFlow(client, nil, true)
			case "tcp":
				live = flow.NewTCPFlow(client, nil, true)
			default:
				http := flow.NewHTTPFlow(client, nil, true)
				if tt.protocol == "websocket" {
					http.WebSocket = &websocket.Data{}
				}
				live = http
			}
			id := live.Common().ID
			if tt.wrongID {
				id = "another-flow"
			}
			err := fixture.handler.Inject(t.Context(), layer.Injected{Flow: live, FlowID: id, Direction: tt.direction, Message: tt.message})
			if !errors.Is(err, tt.want) {
				t.Fatalf("Inject() = %v, want %v", err, tt.want)
			}
			if tt.want != nil {
				if _, ok := errors.AsType[*layer.InjectionError](err); !ok {
					t.Fatalf("rejection has no typed reason: %v", err)
				}
			}
		})
	}
}

func TestHandlerProtocolQueueFullAndClosed(t *testing.T) {
	tests := map[string]struct{ websocket bool }{"UDP": {}, "WebSocket": {websocket: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := startHandler(t, func(ctx context.Context, _ *layer.Context) error { <-ctx.Done(); return ctx.Err() })
			client := &connection.Client{ID: fixture.id(t)}
			live := flow.Flow(flow.NewUDPFlow(client, nil, true))
			message := any(&udp.Message{})
			if tt.websocket {
				http := flow.NewHTTPFlow(client, nil, true)
				http.WebSocket = &websocket.Data{}
				live, message = http, &websocket.Message{Type: websocket.OpBinary}
			}
			injected := layer.Injected{Flow: live, Message: message}
			for range layer.InjectionCapacity {
				if err := fixture.handler.Inject(t.Context(), injected); err != nil {
					t.Fatal(err)
				}
			}
			if err := fixture.handler.Inject(t.Context(), injected); !errors.Is(err, ErrInjectionFull) {
				t.Fatalf("full queue: %v", err)
			}
			if err := fixture.handler.manager.Do(t.Context(), func(context.Context) error { live.Common().Live = false; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := fixture.handler.Inject(t.Context(), injected); !errors.Is(err, ErrFlowNotLive) || !errors.Is(err, ErrInjectionClosed) || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed flow: %v", err)
			}
			fixture.connections.Close()
			if err := await(t, fixture.done); err != nil {
				t.Fatal(err)
			}
			if err := fixture.handler.Inject(t.Context(), injected); !errors.Is(err, ErrInjectionClosed) {
				t.Fatalf("closed connection: %v", err)
			}
		})
	}
}

func TestHandlerProtocolOwnerPublishesSnapshot(t *testing.T) {
	tests := map[string]struct {
		websocket  bool
		fromClient bool
	}{
		"UDP client": {fromClient: true}, "UDP server": {},
		"WebSocket client": {websocket: true, fromClient: true}, "WebSocket server": {websocket: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			owned := make(chan flow.Flow, 1)
			release := make(chan struct{})
			snapshots := make(chan *layer.Snapshot, 1)
			fixture := startHandler(t, func(ctx context.Context, c *layer.Context) error {
				var live flow.Flow
				if tt.websocket {
					f := flow.NewHTTPFlow(c.Data.Client, nil, true)
					f.WebSocket = &websocket.Data{}
					live = f
				} else {
					live = flow.NewUDPFlow(c.Data.Client, nil, true)
				}
				owned <- live
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				var injected layer.Injected
				select {
				case injected = <-c.Inject:
				case <-ctx.Done():
					return ctx.Err()
				}
				if injected.Flow != live || injected.FlowID != live.Common().ID {
					return errors.New("owner received another flow's injection")
				}
				var hook addon.Hook
				if tt.websocket {
					hook = addon.WebSocketMessageHook{Flow: live.(*flow.HTTPFlow)}
				} else {
					hook = addon.UDPMessageHook{Flow: live.(*flow.UDPFlow)}
				}
				snapshot, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
					if tt.websocket {
						f := live.(*flow.HTTPFlow)
						f.WebSocket.Messages = append(f.WebSocket.Messages, injected.Message.(*websocket.Message))
					} else {
						f := live.(*flow.UDPFlow)
						f.Messages = append(f.Messages, injected.Message.(*udp.Message))
					}
					return nil
				}, hook)
				if err != nil {
					return err
				}
				snapshots <- snapshot
				<-ctx.Done()
				return ctx.Err()
			})
			defer func() { fixture.connections.Close(); _ = await(t, fixture.done) }()
			live := await(t, owned)
			payload := []byte("original")
			message := any(&udp.Message{FromClient: tt.fromClient, Content: payload, Timestamp: 123})
			if tt.websocket {
				message = &websocket.Message{Type: websocket.OpText, FromClient: tt.fromClient, Content: payload, Timestamp: 123}
			}
			if err := fixture.handler.Inject(t.Context(), layer.Injected{Flow: live, Message: message}); err != nil {
				t.Fatal(err)
			}
			payload[0] = 'X'
			close(release)
			snapshot := await(t, snapshots)
			if snapshot.NumMessages != 1 {
				t.Fatalf("snapshot count = %d", snapshot.NumMessages)
			}
			if tt.websocket {
				want := &websocket.Message{Type: websocket.OpText, FromClient: tt.fromClient, Content: []byte("original"), Timestamp: 123}
				if diff := gocmp.Diff(want, snapshot.WebSocket.Messages[0]); diff != "" {
					t.Fatalf("WebSocket message (-want +got):\n%s", diff)
				}
			} else {
				want := &udp.Message{FromClient: tt.fromClient, Content: []byte("original"), Timestamp: 123}
				if diff := gocmp.Diff(want, snapshot.LastUDPMessage); diff != "" {
					t.Fatalf("UDP message (-want +got):\n%s", diff)
				}
			}
		})
	}
}
