// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type deadlineLifetimeConn struct {
	net.Conn
	mu        sync.Mutex
	restored  bool
	late      bool
	completed chan struct{}
}

func (c *deadlineLifetimeConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.late = c.late || c.restored
	err := c.Conn.SetDeadline(deadline)
	c.mu.Unlock()
	c.completed <- struct{}{}
	return err
}

func TestRunDeadlineLifetime(t *testing.T) {
	tests := map[string]struct{ client bool }{
		"success: client cancellation cannot overwrite a restored deadline": {client: true},
		"success: server cancellation cannot overwrite a restored deadline": {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for range 100 {
				conn, peer := net.Pipe()
				t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
				transport := &deadlineLifetimeConn{Conn: conn, completed: make(chan struct{}, 2)}
				endpoint, err := New(transport, Config{Client: test.client, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				stopped := make(chan error, 1)
				go func() { stopped <- endpoint.Run(ctx) }()
				cancel()
				guard, stopGuard := context.WithTimeout(t.Context(), 30*time.Second)
				t.Cleanup(stopGuard)
				select {
				case err := <-stopped:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancelled Run = %v", err)
					}
				case <-guard.Done():
					buf := make([]byte, 1<<20)
					t.Fatalf("Run did not release its transport:\n%s", buf[:runtime.Stack(buf, true)])
				}
				transport.mu.Lock()
				transport.restored = true
				err = transport.SetReadDeadline(time.Time{})
				transport.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				// Observe both deadline operations rather than waiting for a scheduling delay.
				for range 2 {
					select {
					case <-transport.completed:
					case <-guard.Done():
						buf := make([]byte, 1<<20)
						t.Fatalf("deadline teardown did not settle:\n%s", buf[:runtime.Stack(buf, true)])
					}
				}
				transport.mu.Lock()
				late := transport.late
				transport.mu.Unlock()
				if diff := gocmp.Diff(false, late); diff != "" {
					t.Fatalf("late deadline callback changed caller-owned transport (-want +got):\n%s", diff)
				}
				stopGuard()
				_ = conn.Close()
				_ = peer.Close()
			}
		})
	}
}
