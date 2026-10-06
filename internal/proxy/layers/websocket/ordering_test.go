// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zchee/gows"
)

func TestProtocolErrorPreservesPendingHook(t *testing.T) {
	tests := map[string]struct{ opcode byte }{
		"reserved second bit":     {0xa1},
		"reserved third bit":      {0x91},
		"reserved data opcode":    {0x83},
		"reserved control opcode": {0x8b},
		"unexpected continuation": {0x80},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for _, fromClient := range []bool{true, false} {
				raw, peer := net.Pipe()
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = raw.Close() })
				wire := []byte{0x81, 1, 'a', tt.opcode, 0}
				if fromClient {
					wire = []byte{0x81, 0x81, 0, 0, 0, 0, 'a', tt.opcode, 0x80, 0, 0, 0, 0}
				}
				conn := gows.NewClientConn(raw, gows.WithBuffered(wire))
				if fromClient {
					conn = gows.NewServerConn(raw, gows.WithBuffered(wire))
				}
				hookCtx, stopHooks := context.WithCancel(t.Context())
				defer stopHooks()
				incoming, failures := make(chan received, 1), make(chan received, 2)
				readMessages(t.Context(), conn, fromClient, incoming, failures, stopHooks)
				event := <-incoming
				if event.op != gows.OpcodeText || event.fromClient != fromClient || !bytes.Equal(event.content, []byte("a")) {
					t.Fatalf("valid preceding message = %+v", event)
				}
				failure := <-failures
				if protocol, ok := errors.AsType[*gows.ProtocolError](failure.err); !ok || protocol.Code != gows.CloseProtocolError {
					t.Fatalf("terminal error = %v, want protocol error", failure.err)
				}
				if err := hookCtx.Err(); err != nil {
					t.Fatalf("protocol error cancelled the valid pending message hook: %v", err)
				}
			}
		})
	}
}

func TestRelayPreservesMessageBeforeProtocolClose(t *testing.T) {
	tests := map[string]struct{ opcode byte }{
		"reserved second bit":     {0xa1},
		"reserved third bit":      {0x91},
		"reserved data opcode":    {0x83},
		"reserved control opcode": {0x8b},
		"unexpected continuation": {0x80},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for _, fromClient := range []bool{true, false} {
				buffers := [2][]byte{nil, {0x81, 1, 'a', tt.opcode, 0}}
				if fromClient {
					buffers = [2][]byte{{0x81, 0x81, 0, 0, 0, 0, 'a', tt.opcode, 0x80, 0, 0, 0, 0}, nil}
				}
				s := newSession(t, nil, false, false, buffers)
				to := s.client
				if fromClient {
					to = s.server
				}
				message := readFrame(t, to)
				if message.Header.Opcode != gows.OpcodeText || !bytes.Equal(message.Payload, []byte("a")) {
					t.Fatalf("first outbound frame = %+v, want the valid preceding text message", message)
				}
				for _, peer := range []*gows.Conn{s.client, s.server} {
					frame := readFrame(t, peer)
					closeInfo, err := gows.ParseClose(frame.Payload)
					if frame.Header.Opcode != gows.OpcodeClose || err != nil || closeInfo.Code != gows.CloseProtocolError {
						t.Fatalf("terminal frame = %+v, parsed %+v, error %v", frame, closeInfo, err)
					}
				}
				if err := await(t, s.done); err == nil {
					t.Fatal("protocol error returned success")
				}
				if s.flow.Live || s.flow.Error == nil || len(s.flow.WebSocket.Messages) != 1 || s.flow.WebSocket.Messages[0].FromClient != fromClient {
					t.Fatalf("terminal flow = %+v, WebSocket = %+v", &s.flow.Base, s.flow.WebSocket)
				}
			}
		})
	}
}

func TestRelayAcceptsManyFragments(t *testing.T) {
	tests := map[string]struct {
		opcode  gows.Opcode
		count   int
		content []byte
	}{
		"four MiB text with sixty-four byte fragments":   {gows.OpcodeText, 65537, bytes.Repeat([]byte("a"), 64)},
		"four MiB binary with sixty-four byte fragments": {gows.OpcodeBinary, 65537, bytes.Repeat([]byte{0xff}, 64)},
		"empty fragments at the limit":                   {gows.OpcodeBinary, 131072, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, nil, false, false)
			written := make(chan error, 1)
			go func() {
				op := tt.opcode
				for i := range tt.count {
					if err := s.client.WriteFrame(op, i == tt.count-1, tt.content, false); err != nil {
						written <- err
						return
					}
					op = gows.OpcodeContinuation
				}
				written <- nil
			}()
			for i := range tt.count {
				frame := readFrame(t, s.server)
				op := gows.OpcodeContinuation
				if i == 0 {
					op = tt.opcode
				}
				if frame.Header.Opcode != op || frame.Header.Fin != (i == tt.count-1) || !bytes.Equal(frame.Payload, tt.content) {
					t.Fatalf("fragment %d = %+v, want opcode %v, fin %v and %d bytes", i, frame, op, i == tt.count-1, len(tt.content))
				}
			}
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
			s.close(t, true, nil)
			if len(s.flow.WebSocket.Messages) != 1 || len(s.flow.WebSocket.Messages[0].Content) != tt.count*len(tt.content) {
				t.Fatalf("message history = %+v", s.flow.WebSocket.Messages)
			}
		})
	}
}
