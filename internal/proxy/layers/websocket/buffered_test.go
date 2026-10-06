// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"io"
	"testing"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func captureFrame(t *testing.T, fromClient, compressed bool, payload []byte) []byte {
	t.Helper()
	writer, reader := layertest.Pipe(t)
	options := []gows.ConnOption{gows.WithCompressionParams(gows.CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true})}
	conn := gows.NewServerConn(writer, options...)
	if fromClient {
		conn = gows.NewClientConn(writer, options...)
	}
	written := make(chan error, 1)
	go func() {
		defer func() { _ = conn.Abort() }()
		written <- conn.WriteFrame(gows.OpcodeBinary, true, payload, compressed)
	}()
	wire, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestBufferedHandoff(t *testing.T) {
	tests := map[string]struct {
		fromClient, compressed bool
		split                  string
	}{
		"client complete masked":     {true, false, "complete"},
		"client partial header":      {true, false, "header"},
		"client partial mask":        {true, false, "mask"},
		"client partial payload":     {true, false, "payload"},
		"client complete compressed": {true, true, "complete"},
		"client partial compressed":  {true, true, "payload"},
		"server complete":            {false, false, "complete"},
		"server partial header":      {false, false, "header"},
		"server partial payload":     {false, false, "payload"},
		"server complete compressed": {false, true, "complete"},
		"server partial compressed":  {false, true, "payload"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("first frame buffered beyond the HTTP 101 head; "), 4)
			wire := captureFrame(t, tt.fromClient, tt.compressed, payload)
			_, headerSize, err := gows.DecodeHeader(wire)
			if err != nil {
				t.Fatal(err)
			}
			split := len(wire)
			switch tt.split {
			case "header":
				split = 1
			case "mask":
				split = headerSize - 2
			case "payload":
				split = headerSize + (len(wire)-headerSize)/2
			}
			prefixes := [2][]byte{}
			side := 1
			if tt.fromClient {
				side = 0
			}
			prefixes[side] = bytes.Clone(wire[:split])
			s := newSession(t, nil, tt.fromClient && tt.compressed, !tt.fromClient && tt.compressed, prefixes)
			raw, src, dst := s.rawServer, s.server, s.client
			if tt.fromClient {
				raw, src, dst = s.rawClient, s.client, s.server
			}
			written := make(chan error, 1)
			go func() {
				if _, err := raw.Write(wire[split:]); err != nil {
					written <- err
					return
				}
				written <- src.WriteFrame(gows.OpcodeText, true, []byte("next"), false)
			}()
			first, next := readFrame(t, dst), readFrame(t, dst)
			if first.Header.Opcode != gows.OpcodeBinary || !first.Header.Fin || first.Compressed || !bytes.Equal(first.Payload, payload) {
				t.Fatalf("buffered frame = %+v, want complete plaintext %q", first, payload)
			}
			if next.Header.Opcode != gows.OpcodeText || string(next.Payload) != "next" {
				t.Fatalf("prefix replayed twice or lost stream bytes: %+v", next)
			}
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
			s.close(t, tt.fromClient, nil)
			if len(s.flow.WebSocket.Messages) != 2 {
				t.Fatalf("messages=%d, want buffered frame and next frame", len(s.flow.WebSocket.Messages))
			}
		})
	}
}
