// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/connection"
)

const maxPendingBytes = 1 << 20

// Stream is a TCP connection with an independently buffered writer.
// Writes below the pending-byte limit return without waiting for the peer.
// A full pending buffer blocks only this stream until space, its write deadline,
// or Close. Close and CloseWrite request a flush followed by FIN, never reset.
type Stream struct {
	conn          net.Conn
	ctx           context.Context
	capacity      func() (bool, <-chan struct{}, error)
	extraInfo     map[string]any
	mu            sync.Mutex
	queue         [][]byte
	pending       int
	closing       bool
	writeErr      error
	writeDeadline time.Time
	changed       chan struct{}
	done          chan struct{}
}

var _ net.Conn = (*Stream)(nil)

func newStream(ctx context.Context, conn net.Conn, capacity func() (bool, <-chan struct{}, error), extraInfo map[string]any) *Stream {
	s := &Stream{ctx: ctx, conn: conn, capacity: capacity, extraInfo: maps.Clone(extraInfo), changed: make(chan struct{}), done: make(chan struct{})}
	go s.writeLoop()
	return s
}

// Read reads buffered peer data before reporting a peer reset or EOF.
// A local full-close request makes subsequent reads fail with net.ErrClosed.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	closed := s.closing
	s.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	n, err := s.conn.Read(p)
	if err != nil {
		s.mu.Lock()
		if s.closing {
			err = net.ErrClosed
		}
		s.mu.Unlock()
	}
	return n, err
}

// Write copies p into the pending queue, returning immediately when it fits.
// At the 1 MiB limit it waits for space, respecting the write deadline and Close.
// Larger writes may be partially queued before cancellation or timeout.
func (s *Stream) Write(p []byte) (int, error) {
	written := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := s.writeErrorLocked(); err != nil {
			return written, err
		}
		if written == len(p) {
			return written, nil
		}
		if available := maxPendingBytes - s.pending; available > 0 {
			var tail []byte
			if len(s.queue) > 0 {
				tail = s.queue[len(s.queue)-1]
			}
			if len(tail) == cap(tail) {
				tail = make([]byte, 0, min(tcpBufferSize, available))
				s.queue = append(s.queue, tail)
			}
			n := min(available, len(p)-written, cap(tail)-len(tail))
			s.queue[len(s.queue)-1] = append(tail, p[written:written+n]...)
			s.pending += n
			written += n
			s.notifyLocked()
			continue
		}
		if err := s.waitLocked(s.ctx, nil); err != nil {
			return written, err
		}
	}
}

// Drain waits for queued bytes to enter TCP's send buffer and for buffer capacity.
// Its context, the write deadline and Close interrupt the wait.
func (s *Stream) Drain(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := s.writeErrorLocked(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var writable <-chan struct{}
		if s.pending == 0 {
			if s.capacity == nil {
				return nil
			}
			ready, changed, err := s.capacity()
			if err != nil || ready {
				return err
			}
			writable = changed
		}
		if err := s.waitLocked(ctx, writable); err != nil {
			return err
		}
	}
}

// Close requests a full close after buffered writes are flushed.
// It returns without waiting for the peer's acknowledgement and is idempotent.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	// Wake reads before allowing the writer to finish and close its endpoint.
	err := s.conn.SetReadDeadline(time.Unix(1, 0))
	s.notifyLocked()
	s.mu.Unlock()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

// CloseWrite is a full-close request, matching the packet engine's lack of half-close.
func (s *Stream) CloseWrite() error { return s.Close() }

// LocalAddr returns the original destination of the inner TCP connection.
func (s *Stream) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// RemoteAddr returns the source of the inner TCP connection.
func (s *Stream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// SetDeadline sets both read and pending-write deadlines; zero disables them.
func (s *Stream) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

// SetReadDeadline changes the deadline for current and future reads.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return net.ErrClosed
	}
	return s.conn.SetReadDeadline(t)
}

// SetWriteDeadline changes the admission deadline for current and future writes.
// Already accepted bytes retain their flush obligation.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return net.ErrClosed
	}
	s.writeDeadline = t
	s.notifyLocked()
	return nil
}

// GetExtraInfo returns transport_protocol as connection.TransportProtocol and
// peername/sockname as net.Addr. Captured original_src/original_dst are
// netip.AddrPort, pid is uint32, and process_name/remote_endpoint are string.
// The boolean is false for an unavailable key; mutable metadata is copied.
func (s *Stream) GetExtraInfo(name string) (any, bool) {
	switch name {
	case "transport_protocol":
		return connection.TCP, true
	case "peername":
		return s.RemoteAddr(), true
	case "sockname":
		return s.LocalAddr(), true
	default:
		value, ok := s.extraInfo[name]
		if data, isBytes := value.([]byte); isBytes {
			value = slices.Clone(data)
		}
		return value, ok
	}
}

func (s *Stream) writeErrorLocked() error {
	if s.closing {
		return net.ErrClosed
	}
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	if s.writeErr != nil {
		return s.writeErr
	}
	if !s.writeDeadline.IsZero() && !time.Now().Before(s.writeDeadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (s *Stream) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Stream) waitLocked(ctx context.Context, writable <-chan struct{}) error {
	changed := s.changed
	var timeout <-chan time.Time
	var timer *time.Timer
	if !s.writeDeadline.IsZero() {
		timer = time.NewTimer(time.Until(s.writeDeadline))
		timeout = timer.C
		defer timer.Stop()
	}
	s.mu.Unlock()
	var err error
	select {
	case <-changed:
	case <-writable:
	case <-ctx.Done():
		err = ctx.Err()
	case <-s.ctx.Done():
		err = s.ctx.Err()
	case <-timeout:
		err = os.ErrDeadlineExceeded
	}
	s.mu.Lock()
	return err
}

func (s *Stream) writeLoop() {
	defer close(s.done)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { defer close(callbackDone); _ = s.conn.Close() })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		s.mu.Lock()
		s.queue = nil
		s.pending = 0
		s.notifyLocked()
		s.mu.Unlock()
	}()
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closing && s.writeErr == nil && s.ctx.Err() == nil {
			changed := s.changed
			s.mu.Unlock()
			select {
			case <-changed:
			case <-s.ctx.Done():
			}
			s.mu.Lock()
		}
		if s.writeErr != nil || s.ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		if len(s.queue) == 0 && s.closing {
			s.mu.Unlock()
			if c, ok := s.conn.(interface{ CloseWrite() error }); ok {
				_ = c.CloseWrite()
			} else {
				_ = s.conn.Close()
			}
			return
		}
		packet := s.queue[0]
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.mu.Unlock()
		n, err := s.conn.Write(packet)
		if n != len(packet) && err == nil {
			err = io.ErrShortWrite
		}
		s.mu.Lock()
		s.pending -= len(packet)
		if err != nil {
			s.writeErr = err
			s.queue = nil
			s.pending = 0
		}
		s.notifyLocked()
		s.mu.Unlock()
		if err != nil {
			_ = s.conn.Close()
			return
		}
	}
}
