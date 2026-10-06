// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bufio"
	"bytes"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

func TestWebSocketHandshakeValidation(t *testing.T) {
	tests := map[string]struct {
		change  func(*websocketHandshake)
		wantErr bool
	}{
		"success: separate valid handshake snapshots":           {},
		"success: mixed case comma-separated Connection tokens": {change: func(h *websocketHandshake) { h.clientRequest.Headers.Set("Connection", "keep-alive, UpGrAdE") }},
		"error: client accept changed by a response hook":       {change: func(h *websocketHandshake) { h.clientResponse.Headers.Set("Sec-WebSocket-Accept", "changed") }, wantErr: true},
		"error: origin accept does not match sent request":      {change: func(h *websocketHandshake) { h.serverResponse.Headers.Set("Sec-WebSocket-Accept", "changed") }, wantErr: true},
		"error: origin rejected upgrade token":                  {change: func(h *websocketHandshake) { h.serverResponse.Headers.Set("Upgrade", "another") }, wantErr: true},
		"error: request key is not a 16-byte nonce":             {change: func(h *websocketHandshake) { h.clientRequest.Headers.Set("Sec-WebSocket-Key", "a2V5") }, wantErr: true},
		"error: required Connection token missing":              {change: func(h *websocketHandshake) { h.serverRequest.Headers.Del("Connection") }, wantErr: true},
		"error: unsupported handshake version":                  {change: func(h *websocketHandshake) { h.clientRequest.Headers.Set("Sec-WebSocket-Version", "12") }, wantErr: true},
		"error: no origin exchange behind synthetic response":   {change: func(h *websocketHandshake) { h.serverRequest = nil }, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			request := &httpmsg.Request{Method: "GET"}
			request.Headers.Set("Connection", "upgrade")
			request.Headers.Set("Upgrade", "websocket")
			request.Headers.Set("Sec-WebSocket-Version", "13")
			request.Headers.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			response := &httpmsg.Response{StatusCode: 101}
			response.Headers.Set("Connection", "Upgrade")
			response.Headers.Set("Upgrade", "websocket")
			response.Headers.Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
			h := websocketHandshake{clientRequest: request.Clone(), serverRequest: request.Clone(), clientResponse: response.Clone(), serverResponse: response.Clone()}
			if tt.change != nil {
				tt.change(&h)
			}
			if err := h.validate(); (err != nil) != tt.wantErr {
				t.Fatalf("handshake error = %v, want error = %v", err, tt.wantErr)
			}
		})
	}
}

func TestHTTP1ProtocolTakeoverExact(t *testing.T) {
	tests := map[string]struct{ leading string }{
		"success: binary frame prefix":                     {leading: "\x82\x03"},
		"success: leading newline bytes are protocol data": {leading: "\r\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := http1Conn{src: &pushbackReader{prefix: []byte("source")}, br: bufio.NewReader(bytes.NewBufferString("buffered")), waitBuf: []byte(tt.leading + "waiting")}
			if _, err := c.br.Peek(1); err != nil {
				t.Fatal(err)
			}
			want := []byte(tt.leading + "waitingbufferedsource")
			if diff := gocmp.Diff(want, c.takeoverExact()); diff != "" {
				t.Fatal(diff)
			}
			if c.state != http1Done || len(c.takeoverExact()) != 0 || c.src.prefix != nil {
				t.Fatal("takeover left bytes available to a second reader")
			}
		})
	}
}
