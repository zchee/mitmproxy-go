// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package udplayer

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

func TestBuildRequiresPackets(t *testing.T) {
	tests := map[string]struct{ ignore bool }{"captured": {}, "ignored": {ignore: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := &layer.Context{Data: new(hookdata.Context), Do: func(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }}
			selected, err := layer.Build(t.Context(), c, hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: test.ignore}})
			if err == nil || selected != nil {
				t.Fatalf("stream-only UDP build = %v, %v", selected, err)
			}
		})
	}
}

func TestReadPackets(t *testing.T) {
	tests := map[string]struct{ first, second []byte }{
		"retained content does not alias read window": {first: []byte("first"), second: []byte("second")},
		"empty datagram is not EOF":                   {second: []byte("after empty")},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			input, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener := packettransport.NewListener(t.Context(), input)
			t.Cleanup(func() { _ = listener.Close() })
			peer, err := net.DialUDP("udp", nil, input.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			if _, err := peer.Write(test.first); err != nil {
				t.Fatal(err)
			}
			inputTuple, err := listener.Accept(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			incoming, done := make(chan received, 1), make(chan struct{})
			go func() { defer close(done); readPackets(ctx, inputTuple, true, incoming) }()
			t.Cleanup(func() {
				cancel()
				_ = inputTuple.Close()
				select {
				case <-done:
				case <-time.After(30 * time.Second):
					stack := make([]byte, 64<<10)
					n := runtime.Stack(stack, true)
					t.Fatalf("packet reader did not join:\n%s", stack[:n])
				}
			})
			read := func() received {
				select {
				case event := <-incoming:
					return event
				case <-time.After(30 * time.Second):
					stack := make([]byte, 64<<10)
					n := runtime.Stack(stack, true)
					t.Fatalf("packet reader did not deliver datagram:\n%s", stack[:n])
					return received{}
				}
			}
			first := read()
			if _, err := peer.Write(test.second); err != nil {
				t.Fatal(err)
			}
			second := read()
			if diff := gocmp.Diff(string(test.first), string(first.content)); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(string(test.second), string(second.content)); diff != "" {
				t.Fatal(diff)
			}
			if first.err != nil || second.err != nil || !first.fromClient || !second.fromClient {
				t.Fatalf("packet events: first=%+v second=%+v", first, second)
			}
		})
	}
}
