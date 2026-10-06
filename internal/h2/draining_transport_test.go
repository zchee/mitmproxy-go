// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestDrainingTerminalRead(t *testing.T) {
	roles := map[string]struct{ client bool }{"client": {client: true}, "server": {}}
	for role, config := range roles {
		t.Run(role, func(t *testing.T) {
			tests := map[string]struct {
				terminal error
				complete bool
			}{
				"success: completed response survives EOF":   {terminal: io.EOF, complete: true},
				"success: completed response survives reset": {terminal: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, complete: true},
				"error: incomplete response retains EOF":     {terminal: io.EOF},
				"error: incomplete response retains reset":   {terminal: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}},
			}
			if runtime.GOOS == "windows" {
				const wsaECONNRESET = syscall.Errno(10054)
				tests["success: completed response survives Windows reset"] = struct {
					terminal error
					complete bool
				}{terminal: &net.OpError{Op: "read", Net: "tcp", Err: wsaECONNRESET}, complete: true}
			}
			for name, test := range tests {
				t.Run(name, func(t *testing.T) {
					conn, peer := net.Pipe()
					t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
					endpoint, err := New(conn, Config{Client: config.client, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					owner := newOwner(endpoint, ctx)
					owner.controls = nil
					owner.peerSettings, owner.goaway, owner.shutdown = true, true, true
					endpoint.draining.Store(true)
					stream := owner.newStream(1)
					if stream == nil {
						t.Fatal("could not reserve stream")
					}
					stream.localEnd, stream.remoteEnd = true, test.complete
					stream.queue = []queuedEvent{{event: Event{Kind: Data, Identity: stream.id, Data: []byte("tail"), EndStream: test.complete}, original: 4}}
					reads := make(chan readFrame)
					stopped := make(chan error, 1)
					var workers sync.WaitGroup
					workers.Go(func() {
						err := owner.run(reads, nil, nil)
						owner.closeAll(err)
						endpoint.failure.Store(&result{err: err})
						close(endpoint.done)
						stopped <- err
					})
					t.Cleanup(func() { cancel(); workers.Wait() })
					select {
					case reads <- readFrame{err: test.terminal}:
					case <-ctx.Done():
						buf := make([]byte, 1<<20)
						t.Fatalf("owner did not accept terminal read:\n%s", buf[:runtime.Stack(buf, true)])
					}
					body, err := endpoint.ReceiveStream(ctx, stream.id)
					if !test.complete {
						if !errors.Is(err, test.terminal) {
							t.Fatalf("incomplete response = %+v, %v; want %v", body, err, test.terminal)
						}
						return
					}
					if err != nil {
						t.Fatalf("completed response lost its final event: %v", err)
					}
					if diff := gocmp.Diff("tail", string(body.Data)); diff != "" {
						t.Fatal(diff)
					}
					if !body.EndStream || body.Receipt == nil || !body.Receipt.Complete() {
						t.Fatal("final event was not delivered with its consumption receipt")
					}
					select {
					case err := <-stopped:
						if err != nil {
							t.Fatalf("drained owner = %v", err)
						}
					case <-ctx.Done():
						buf := make([]byte, 1<<20)
						t.Fatalf("owner did not finish draining:\n%s", buf[:runtime.Stack(buf, true)])
					}
				})
			}
		})
	}
}
