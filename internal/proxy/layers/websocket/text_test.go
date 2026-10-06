// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"context"
	"testing"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/flow"
	wsmodel "github.com/zchee/mitmproxy-go/websocket"
)

func TestRelayOriginalOpcodeAndWholeTextReplacement(t *testing.T) {
	tests := map[string]struct {
		op            gows.Opcode
		editType      wsmodel.Opcode
		content, want []byte
	}{
		"text keeps original opcode":             {gows.OpcodeText, wsmodel.OpBinary, []byte("edited"), []byte("edited")},
		"binary keeps original opcode":           {gows.OpcodeBinary, wsmodel.OpText, []byte{0xff}, []byte{0xff}},
		"invalid text replaced as whole message": {gows.OpcodeText, wsmodel.OpText, []byte{0xff, 'x', 0xc3}, []byte("�x�")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, &observer{message: func(_ context.Context, f *flow.HTTPFlow) error {
				m := f.WebSocket.Messages[len(f.WebSocket.Messages)-1]
				m.Type, m.Content = tt.editType, bytes.Clone(tt.content)
				return nil
			}}, false, false)
			written := make(chan error, 1)
			go func() { written <- s.client.WriteFrame(tt.op, true, []byte("original"), false) }()
			frame := readFrame(t, s.server)
			if frame.Header.Opcode != tt.op || !bytes.Equal(frame.Payload, tt.want) {
				t.Fatalf("frame opcode=%v payload=%x, want opcode=%v payload=%x", frame.Header.Opcode, frame.Payload, tt.op, tt.want)
			}
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
			s.close(t, true, nil)
		})
	}
}

func TestRelaySplitCodePointPreservesBytes(t *testing.T) {
	s := newSession(t, nil, false, false)
	fragments := [][]byte{{0xe2}, {0x82}, {0xac}}
	written := make(chan error, 1)
	go func() {
		op := gows.OpcodeText
		for i, part := range fragments {
			if err := s.client.WriteFrame(op, i == len(fragments)-1, part, false); err != nil {
				written <- err
				return
			}
			op = gows.OpcodeContinuation
		}
		written <- nil
	}()
	for i, want := range fragments {
		frame := readFrame(t, s.server)
		if !bytes.Equal(frame.Payload, want) || frame.Header.Fin != (i == len(fragments)-1) {
			t.Fatalf("fragment %d = %+v, want %x", i, frame, want)
		}
	}
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	s.close(t, true, nil)
}
