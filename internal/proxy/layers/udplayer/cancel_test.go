// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package udplayer

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestRelayCancellationError(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	tests := map[string]struct{ afterWrite, duringWrite bool }{
		"error: cancellation wins over interrupted packet readers":            {},
		"error: cancelled owner receives pending reader failure":              {afterWrite: true},
		"error: cancellation during a relayed write is not a transport fault": {duringWrite: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.afterWrite {
				ctx = &valueFreeContext{Context: ctx}
			}
			transports := [2]*observedPacketRead{}
			peers := [2]net.PacketConn{}
			for i := range transports {
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = socket.Close() })
				peer, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = peer.Close() })
				peers[i] = peer
				transports[i] = &observedPacketRead{PacketConn: socket, ctx: t.Context(), remote: peer.LocalAddr(), started: make(chan struct{}), failed: make(chan struct{}), deadlineSet: make(chan struct{})}
			}
			if test.afterWrite {
				transports[1].afterWrite = func() {
					if err := transports[0].SetReadDeadline(time.Now()); err != nil {
						t.Error(err)
					}
					awaitTerminal(t, transports[0].failed)
					cancel()
				}
			}
			if test.duringWrite {
				// Cancel while the relay is inside WriteTo: the interrupt sets an
				// immediate deadline on both transports, so the write itself fails
				// with a deadline error that must not be reported as the outcome.
				transports[1].beforeWrite = func() {
					cancel()
					awaitTerminal(t, transports[1].deadlineSet)
				}
			}
			c := &layer.Context{
				ClientPackets: proxy.RecordPackets(transports[0]),
				ServerPackets: proxy.RecordPackets(transports[1]),
			}
			c.ClientPackets.StopRecording()
			c.ServerPackets.StopRecording()
			done := make(chan error, 1)
			go func() { done <- new(udpLayer).relay(ctx, c) }()
			for _, transport := range transports {
				awaitTerminal(t, transport.started)
			}
			if test.afterWrite || test.duringWrite {
				if _, err := peers[0].WriteTo([]byte("request"), transports[0].LocalAddr()); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			if err := awaitTerminal(t, done); !errors.Is(err, context.Canceled) {
				t.Fatalf("relay cancellation = %v, want context.Canceled", err)
			}
		})
	}
}

// A custom context need not expose its parent's values. Cancellation then
// propagates asynchronously to derived contexts, so a pending reader result
// can stay selectable after the owner's context has been cancelled.
type valueFreeContext struct{ context.Context }

func (*valueFreeContext) Value(any) any { return nil }

// observedPacketRead uses real sockets and signals entry into blocking reads.
// Its transport context stays live so relay cancellation must interrupt I/O
// through deadlines, rather than relying on closing the underlying socket.
type observedPacketRead struct {
	net.PacketConn
	ctx         context.Context
	remote      net.Addr
	started     chan struct{}
	failed      chan struct{}
	deadlineSet chan struct{}
	once        sync.Once
	deadline    sync.Once
	beforeWrite func()
	afterWrite  func()
}

func (c *observedPacketRead) Context() context.Context { return c.ctx }
func (c *observedPacketRead) RemoteAddr() net.Addr     { return c.remote }

func (c *observedPacketRead) ReadFrom(p []byte) (int, net.Addr, error) {
	c.once.Do(func() { close(c.started) })
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		close(c.failed)
	}
	return n, addr, err
}

// SetDeadline records the relay's interrupt so a test can order its write
// after the deadline has been armed.
func (c *observedPacketRead) SetDeadline(t time.Time) error {
	if !t.IsZero() && c.deadlineSet != nil {
		c.deadline.Do(func() { close(c.deadlineSet) })
	}
	return c.PacketConn.SetDeadline(t)
}

func (c *observedPacketRead) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		addr = c.remote
	}
	if c.beforeWrite != nil {
		c.beforeWrite()
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil && c.afterWrite != nil {
		c.afterWrite()
	}
	return n, err
}
