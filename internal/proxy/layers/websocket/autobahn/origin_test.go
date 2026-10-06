// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/zchee/gows"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestPreferredListener(t *testing.T) {
	tests := map[string]struct{ busy bool }{"free": {}, "busy": {true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			address := "127.0.0.1:0"
			if tt.busy {
				held, err := net.Listen("tcp", address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = held.Close() })
				address = held.Addr().String()
			}
			listener, err := preferredListener(address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if tt.busy && listener.Addr().String() == address {
				t.Fatal("busy port was not replaced")
			}
		})
	}
	if listener, err := preferredListener("127.0.0.1:invalid"); err == nil {
		_ = listener.Close()
		t.Fatal("invalid configuration silently fell back")
	}
}

func TestOriginEchoAndControls(t *testing.T) {
	tests := map[string]struct {
		compressed, wantCompressed bool
		payload                    []byte
	}{
		"plaintext":                {false, false, []byte("echo a complete text message")},
		"small negotiated message": {true, false, []byte("small")},
		"compressed":               {true, true, bytes.Repeat([]byte("compress this message"), 256)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			address, stop, err := startOrigin("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := stop(); err != nil {
					t.Error(err)
				}
			})
			dialer := gows.Dialer{EnableCompression: tt.compressed}
			raw, handshake, err := dialer.Dial(t.Context(), "ws://"+address)
			if err != nil {
				t.Fatal(err)
			}
			options := []gows.ConnOption{gows.WithBuffered(handshake.Buffered)}
			if handshake.Compressed {
				options = append(options, gows.WithCompressionParams(handshake.CompressionParams))
			}
			client := gows.NewClientConn(raw, options...)
			t.Cleanup(func() { _ = client.Abort() })
			if err := client.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			read := func() gows.Frame {
				frame, err := client.ReadFrame()
				if err != nil {
					buf := make([]byte, 1<<20)
					n := runtime.Stack(buf, true)
					t.Fatalf("frame read: %v\n%s", err, buf[:n])
				}
				return frame
			}
			if err := client.WriteFrame(gows.OpcodePing, true, []byte("ping"), false); err != nil {
				t.Fatal(err)
			}
			if pong := read(); pong.Header.Opcode != gows.OpcodePong || string(pong.Payload) != "ping" {
				t.Fatalf("pong=%+v", pong)
			}
			payload := tt.payload
			if err := client.WriteFrame(gows.OpcodeText, true, payload, tt.compressed); err != nil {
				t.Fatal(err)
			}
			frame := read()
			plain, complete, err := client.DecodeFrame(frame)
			if err != nil || !complete || !bytes.Equal(plain, payload) || frame.Compressed != tt.wantCompressed {
				t.Fatalf("echo=%+v plain=%q complete=%v error=%v", frame, plain, complete, err)
			}
			if err := client.WriteFrame(gows.OpcodeClose, true, gows.AppendCloseBody(nil, gows.CloseNormalClosure, []byte("done")), false); err != nil {
				t.Fatal(err)
			}
			if closeFrame := read(); closeFrame.Header.Opcode != gows.OpcodeClose {
				t.Fatalf("close=%+v", closeFrame)
			}
		})
	}
}
