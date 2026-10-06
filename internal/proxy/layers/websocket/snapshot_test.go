// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"context"
	"testing"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	wsmodel "github.com/zchee/mitmproxy-go/websocket"
)

type mutateAfterSnapshotHooks struct {
	layer.Hooks
	do func(context.Context, func(context.Context) error) error
}

func (h *mutateAfterSnapshotHooks) FireFunc(ctx context.Context, prepare func(context.Context) error, hook addon.Hook) (*layer.Snapshot, error) {
	snapshot, err := h.Hooks.FireFunc(ctx, prepare, hook)
	messageHook, ok := hook.(addon.WebSocketMessageHook)
	if err != nil || !ok {
		return snapshot, err
	}
	// The real Handler runner has already captured its snapshot. Mutate the
	// live flow under dispatch before the relay can select outbound behavior.
	err = h.do(ctx, func(context.Context) error {
		f := messageHook.Flow
		m := f.WebSocket.Messages[len(f.WebSocket.Messages)-1]
		m.Content[0] = 'X'
		m.Type = wsmodel.OpBinary
		m.FromClient = !m.FromClient
		m.Drop()
		f.WebSocket.Messages = append(f.WebSocket.Messages, &wsmodel.Message{Type: wsmodel.OpBinary, Content: []byte("newer live message")})
		return f.Kill()
	})
	return snapshot, err
}

func TestHandlerOutboundUsesOnlySnapshot(t *testing.T) {
	tests := map[string]struct{ fromClient bool }{"client": {true}, "server": {false}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newHandlerSession(t, nil, handlerSnapshotKind)
			from, to := s.server, s.client
			if tt.fromClient {
				from, to = s.client, s.server
			}
			written := make(chan error, 1)
			go func() {
				if err := from.WriteFrame(gows.OpcodeText, false, []byte("unc"), false); err != nil {
					written <- err
					return
				}
				written <- from.WriteFrame(gows.OpcodeContinuation, true, []byte("hanged!"), false)
			}()
			for i, want := range []string{"unc", "hanged!"} {
				frame := readFrame(t, to)
				op := gows.OpcodeText
				if i > 0 {
					op = gows.OpcodeContinuation
				}
				if frame.Header.Opcode != op || frame.Header.Fin != (i == 1) || string(frame.Payload) != want {
					t.Fatalf("snapshot fragment = %+v, want %q", frame, want)
				}
			}
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
			s.close(t, tt.fromClient, nil)
			if string(s.flow.WebSocket.Messages[0].Content) != "Xnchanged!" || !s.flow.WebSocket.Messages[0].Dropped || len(s.flow.WebSocket.Messages) != 2 {
				t.Fatalf("live mutations did not take effect: %+v", s.flow.WebSocket.Messages)
			}
		})
	}
}
