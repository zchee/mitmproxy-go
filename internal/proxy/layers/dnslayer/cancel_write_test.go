// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// cancelWritePackets cancels at the actual UDP write boundary, then expires the
// real transport's write deadline. It delegates the I/O and error to that socket.
type cancelWritePackets struct {
	layer.PacketRecorder
	cancel    context.CancelFunc
	attempted chan error
}

func (r cancelWritePackets) WriteTo(p []byte, peer net.Addr) (int, error) {
	r.cancel()
	if err := r.SetWriteDeadline(time.Now()); err != nil {
		return 0, err
	}
	n, err := r.PacketRecorder.WriteTo(p, peer)
	r.attempted <- err
	return n, err
}

func TestCancellationWinsDuringUDPWrite(t *testing.T) {
	s := newSession(t, true, &observer{request: func(_ context.Context, f *flow.DNSFlow) error {
		f.Response = f.Request.Succeed(nil)
		return nil
	}})
	attempted := make(chan error, 1)
	s.context.ClientPackets = cancelWritePackets{PacketRecorder: s.context.ClientPackets, cancel: func() { s.cancel() }, attempted: attempted}
	s.start(t)
	s.write(t, query(41))
	if err := await(t, s.done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost to write result: %v", err)
	}
	await(t, s.finished)
	if err := await(t, attempted); err == nil {
		t.Fatal("expired real UDP write deadline did not fail")
	}
}
