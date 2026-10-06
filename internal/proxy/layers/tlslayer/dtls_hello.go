// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

// readDTLSClientHello consumes ordered packets through a recording transport;
// the caller rewinds that transport before the handshake. The fixed head timer
// starts before the first read and cannot be extended by trickled packets.
func readDTLSClientHello(ctx context.Context, conn layer.PacketTransport, clock layer.Clock) (hello *tlsparse.ClientHello, err error) {
	if clock == nil {
		clock = layer.WallClock
	}
	var expired atomic.Bool
	timedOut := make(chan struct{})
	stopTimer := clock.AfterFunc(layer.HeadReadTimeout, func() {
		expired.Store(true)
		// The clock schedules expiry; this past socket deadline only wakes I/O.
		_ = conn.SetReadDeadline(time.Unix(1, 0))
		close(timedOut)
	})
	cancelled := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Unix(1, 0))
		close(cancelled)
	})
	defer func() {
		// Join callbacks before handing the transport to pion: Stop alone does
		// not wait for an executing callback to finish setting its deadline.
		if !stopTimer() {
			<-timedOut
		}
		if !stopCancel() {
			<-cancelled
		}
		_ = conn.SetReadDeadline(time.Time{})
		if ctx.Err() != nil {
			hello, err = nil, ctx.Err()
		} else if expired.Load() {
			hello, err = nil, os.ErrDeadlineExceeded
		}
	}()
	const maxWireBytes = 128 << 10
	wire := make([]byte, 0, 2048)
	packet := make([]byte, layer.MaxUDPPacketBytes+1)
	for range layer.PacketQueueCapacity {
		n, _, readErr := conn.ReadFrom(packet)
		if readErr != nil {
			return nil, readErr
		}
		if n > layer.MaxUDPPacketBytes || len(wire)+n > maxWireBytes {
			return nil, layer.ErrRecordSize
		}
		wire = append(wire, packet[:n]...)
		hello, err = tlsparse.ParseDTLSClientHello(wire)
		if hello != nil || err != nil {
			return hello, err
		}
	}
	return nil, layer.ErrRecordSize
}
