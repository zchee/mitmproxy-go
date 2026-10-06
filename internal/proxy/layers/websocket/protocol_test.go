// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/flow"
)

func TestRelayCloseMetadata(t *testing.T) {
	tests := map[string]struct {
		fromClient bool
		code       gows.CloseCode
		reason     string
	}{
		"client without code":     {true, 0, ""},
		"server without code":     {false, 0, ""},
		"client with normal code": {true, gows.CloseNormalClosure, "done"},
		"server with custom code": {false, 3000, "server finished"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			observed := &observer{started: make(chan *flow.HTTPFlow, 1)}
			s := newSession(t, observed, false, false)
			await(t, observed.started)
			var payload []byte
			if tt.code != 0 {
				payload = gows.AppendCloseBody(nil, tt.code, []byte(tt.reason))
			}
			s.close(t, tt.fromClient, payload)
			data := s.flow.WebSocket
			if data.ClosedByClient == nil || *data.ClosedByClient != tt.fromClient || data.TimestampEnd == nil || data.CloseReason == nil || *data.CloseReason != tt.reason {
				t.Fatalf("terminal metadata=%+v", data)
			}
			if tt.code == 0 {
				if data.CloseCode != nil {
					t.Fatalf("absent code changed: %d", *data.CloseCode)
				}
			} else if data.CloseCode == nil || *data.CloseCode != int(tt.code) {
				t.Fatalf("code=%v, want %d", data.CloseCode, tt.code)
			}
			if s.flow.Error != nil {
				t.Fatalf("normal close produced flow error: %v", s.flow.Error)
			}
			if diff := gocmp.Diff([]string{"websocket_start", "websocket_end"}, s.observed.events); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestRelayProtocolErrors(t *testing.T) {
	tests := map[string]struct {
		fromClient bool
		wire       []byte
		code       gows.CloseCode
	}{
		"reserved opcode": {true, []byte{0x8f, 0x80, 0, 0, 0, 0}, gows.CloseProtocolError},
		"unmasked client": {true, []byte{0x81, 0x00}, gows.CloseProtocolError},
		"masked server":   {false, []byte{0x81, 0x80, 0, 0, 0, 0}, gows.CloseProtocolError},
		"invalid text":    {true, []byte{0x81, 0x81, 0, 0, 0, 0, 0xff}, gows.CloseInvalidFramePayloadData},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			observed := &observer{started: make(chan *flow.HTTPFlow, 1)}
			s := newSession(t, observed, false, false)
			await(t, observed.started)
			source := s.rawServer
			if tt.fromClient {
				source = s.rawClient
			}
			written := make(chan error, 1)
			go func() { _, err := source.Write(tt.wire); written <- err }()
			for _, peer := range []*gows.Conn{s.client, s.server} {
				frame := readFrame(t, peer)
				close, err := gows.ParseClose(frame.Payload)
				if frame.Header.Opcode != gows.OpcodeClose || err != nil || close.Code != tt.code {
					t.Fatalf("protocol close=%+v parsed=%+v error=%v", frame, close, err)
				}
			}
			// A malformed header can be rejected before all input bytes are consumed.
			_ = await(t, written)
			if err := await(t, s.done); err == nil {
				t.Fatal("protocol error returned success")
			}
			if s.flow.Live || s.flow.Error == nil || s.flow.WebSocket.CloseCode == nil || *s.flow.WebSocket.CloseCode != int(tt.code) {
				t.Fatalf("flow=%+v websocket=%+v", &s.flow.Base, s.flow.WebSocket)
			}
			if diff := gocmp.Diff([]string{"websocket_start", "websocket_end"}, s.observed.events); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestRelayPingPongBothDirections(t *testing.T) {
	tests := map[string]struct {
		fromClient bool
		op         gows.Opcode
	}{
		"client ping": {true, gows.OpcodePing}, "server ping": {false, gows.OpcodePing},
		"client pong": {true, gows.OpcodePong}, "server pong": {false, gows.OpcodePong},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			observed := &observer{started: make(chan *flow.HTTPFlow, 1)}
			s := newSession(t, observed, false, false)
			await(t, observed.started)
			from, to := s.server, s.client
			if tt.fromClient {
				from, to = s.client, s.server
			}
			payload := []byte{0, 1, 0xfe, 0xff}
			written := make(chan error, 1)
			go func() { written <- from.WriteFrame(tt.op, true, payload, false) }()
			frame := readFrame(t, to)
			if frame.Header.Opcode != tt.op || !frame.Header.Fin || !bytes.Equal(frame.Payload, payload) {
				t.Fatalf("control=%+v", frame)
			}
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
			// Close must be next on both peers: an automatic Pong would fail this.
			s.close(t, true, nil)
			if len(s.flow.WebSocket.Messages) != 0 {
				t.Fatal("control frame became a data message")
			}
		})
	}
}

func TestRelayAbnormalDisconnectMetadata(t *testing.T) {
	tests := map[string]struct{ fromClient bool }{"client": {true}, "server": {false}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			observed := &observer{started: make(chan *flow.HTTPFlow, 1)}
			s := newSession(t, observed, false, false)
			await(t, observed.started)
			closed, other := s.rawServer, s.client
			if tt.fromClient {
				closed, other = s.rawClient, s.server
			}
			if err := closed.Close(); err != nil {
				t.Fatal(err)
			}
			if err := await(t, s.done); err == nil {
				t.Fatal("abnormal disconnect returned success")
			}
			data := s.flow.WebSocket
			if s.flow.Live || s.flow.Error == nil || data.CloseCode == nil || *data.CloseCode != 1006 || data.ClosedByClient == nil || *data.ClosedByClient != tt.fromClient || data.TimestampEnd == nil {
				t.Fatalf("flow=%+v websocket=%+v", &s.flow.Base, data)
			}
			if frame, err := other.ReadFrame(); err == nil {
				t.Fatalf("abnormal code must not be sent on the wire: %+v", frame)
			}
			if diff := gocmp.Diff([]string{"websocket_start", "websocket_end"}, s.observed.events); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
