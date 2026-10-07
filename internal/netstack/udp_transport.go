// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

const (
	udpPacketLimit = 64
	udpByteLimit   = 1 << 20
)

type udpTransport struct {
	conn         net.PacketConn
	remote       net.Addr
	ctx          context.Context
	cancel       context.CancelCauseFunc
	extraInfo    map[string]any
	touch        func()
	evict        func()
	mu           sync.Mutex
	closed       bool
	packets      [][]byte
	bytes        int
	readDeadline time.Time
	changed      chan struct{}
	done         chan struct{}
}

var _ layer.PacketTransport = (*udpTransport)(nil)

func newUDPTransport(parent context.Context, conn net.PacketConn, remote net.Addr, info map[string]any, touch, evict func()) *udpTransport {
	ctx, cancel := context.WithCancelCause(parent)
	t := &udpTransport{conn: conn, remote: remote, ctx: ctx, cancel: cancel, extraInfo: maps.Clone(info), touch: touch, evict: evict, changed: make(chan struct{}), done: make(chan struct{})}
	return t
}

func (t *udpTransport) receive() {
	defer close(t.done)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(t.ctx, func() { defer close(callbackDone); _ = t.conn.Close() })
	defer func() {
		if !stop() {
			<-callbackDone
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, _, err := t.conn.ReadFrom(buf)
		if err != nil {
			t.closeWithError(err)
			return
		}
		t.mu.Lock()
		if t.ctx.Err() != nil {
			t.mu.Unlock()
			t.closeWithError(context.Cause(t.ctx))
			return
		}
		if len(t.packets) >= udpPacketLimit || t.bytes+n > udpByteLimit {
			t.mu.Unlock()
			t.closeWithError(ErrQueueFull)
			return
		}
		t.packets = append(t.packets, slices.Clone(buf[:n]))
		t.bytes += n
		t.notifyLocked()
		t.mu.Unlock()
	}
}

func (t *udpTransport) ReadFrom(p []byte) (int, net.Addr, error) {
	t.touch()
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		if t.ctx.Err() != nil {
			return 0, nil, t.closedError()
		}
		if !t.readDeadline.IsZero() && !time.Now().Before(t.readDeadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		if len(t.packets) > 0 {
			packet := t.packets[0]
			t.packets[0] = nil
			t.packets = t.packets[1:]
			t.bytes -= len(packet)
			return copy(p, packet), t.remote, nil
		}
		changed := t.changed
		var timer *time.Timer
		var timeout <-chan time.Time
		if !t.readDeadline.IsZero() {
			timer = time.NewTimer(time.Until(t.readDeadline))
			timeout = timer.C
		}
		t.mu.Unlock()
		select {
		case <-changed:
		case <-t.ctx.Done():
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
		t.mu.Lock()
	}
}

func (t *udpTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	if t.ctx.Err() != nil {
		return 0, t.closedError()
	}
	if addr == nil || addr.Network() != t.remote.Network() || addr.String() != t.remote.String() {
		return 0, fmt.Errorf("UDP peer differs from fixed tuple: %v", addr)
	}
	if len(p) > 65507 {
		return 0, fmt.Errorf("UDP payload too large: %d", len(p))
	}
	t.touch()
	n, err := t.conn.WriteTo(p, addr)
	if t.ctx.Err() != nil {
		return n, t.closedError()
	}
	return n, err
}

func (t *udpTransport) Close() error { t.closeWithError(net.ErrClosed); return nil }

func (t *udpTransport) closeWithError(cause error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.cancel(cause)
	t.packets = nil
	t.bytes = 0
	t.notifyLocked()
	t.mu.Unlock()
	_ = t.conn.Close()
	t.evict()
}

func (t *udpTransport) closedError() error {
	return errors.Join(net.ErrClosed, t.ctx.Err(), context.Cause(t.ctx))
}
func (t *udpTransport) Context() context.Context { return t.ctx }
func (t *udpTransport) LocalAddr() net.Addr      { return t.conn.LocalAddr() }
func (t *udpTransport) RemoteAddr() net.Addr     { return t.remote }
func (t *udpTransport) SetDeadline(d time.Time) error {
	if err := t.SetReadDeadline(d); err != nil {
		return err
	}
	return t.SetWriteDeadline(d)
}

func (t *udpTransport) SetReadDeadline(d time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ctx.Err() != nil {
		return t.closedError()
	}
	t.readDeadline = d
	t.notifyLocked()
	return nil
}

func (t *udpTransport) SetWriteDeadline(d time.Time) error {
	if t.ctx.Err() != nil {
		return t.closedError()
	}
	return t.conn.SetWriteDeadline(d)
}

func (t *udpTransport) GetExtraInfo(name string) (any, bool) {
	switch name {
	case "transport_protocol":
		return connection.UDP, true
	case "peername":
		return t.RemoteAddr(), true
	case "sockname":
		return t.LocalAddr(), true
	default:
		v, ok := t.extraInfo[name]
		if p, isBytes := v.([]byte); isBytes {
			v = slices.Clone(p)
		}
		return v, ok
	}
}
func (t *udpTransport) notifyLocked() { close(t.changed); t.changed = make(chan struct{}) }
