// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"errors"
	"testing"

	"github.com/zchee/gows"
)

func TestRelayFragmentLimit(t *testing.T) {
	s := newSession(t, nil, false, false)
	written := make(chan error, 1)
	go func() {
		op := gows.OpcodeBinary
		for range maxFragmentsPerMessage + 1 {
			if err := s.client.WriteFrame(op, false, nil, false); err != nil {
				written <- err
				return
			}
			op = gows.OpcodeContinuation
		}
		written <- nil
	}()
	for _, peer := range []*gows.Conn{s.client, s.server} {
		frame := readFrame(t, peer)
		closeInfo, err := gows.ParseClose(frame.Payload)
		if err != nil || frame.Header.Opcode != gows.OpcodeClose || closeInfo.Code != gows.CloseMessageTooBig {
			t.Fatalf("close frame = %+v, parsed %+v, error %v", frame, closeInfo, err)
		}
	}
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	err := await(t, s.done)
	if protocol, ok := errors.AsType[*gows.ProtocolError](err); !ok || protocol.Code != gows.CloseMessageTooBig {
		t.Fatalf("termination error = %v, want 1009 ProtocolError", err)
	}
	if s.flow.Error == nil || s.flow.Live || len(s.flow.WebSocket.Messages) != 0 {
		t.Fatalf("terminal flow: live=%v error=%v messages=%d", s.flow.Live, s.flow.Error, len(s.flow.WebSocket.Messages))
	}
	if *s.flow.WebSocket.CloseCode != 1009 {
		t.Fatalf("close code = %d", *s.flow.WebSocket.CloseCode)
	}
}

func TestRelayCancellationEndsOnce(t *testing.T) {
	s := newSession(t, nil, false, false)
	s.cancel()
	if err := await(t, s.done); err == nil {
		t.Fatal("cancelled relay returned no error")
	}
	ends := 0
	for _, name := range s.observed.events {
		if name == "websocket_end" {
			ends++
		}
	}
	if ends != 1 || s.flow.Live || s.flow.WebSocket.TimestampEnd == nil {
		t.Fatalf("ends=%d live=%v metadata=%+v", ends, s.flow.Live, s.flow.WebSocket)
	}
}
