// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layertest

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// MemoryPipe returns an in-memory connection pair with working half-close
// semantics. Both endpoints close in cleanup. Callers bound their own waits.
// Writes are synchronous, so fuzz targets can control read segmentation.
func MemoryPipe(tb testing.TB) (a, b layer.Conn) {
	tb.Helper()
	ar, bw := net.Pipe()
	br, aw := net.Pipe()
	ab := &memoryDirection{reader: br, writer: aw}
	ba := &memoryDirection{reader: ar, writer: bw}
	a = &memoryConn{Conn: ar, writer: aw, readDirection: ba, writeDirection: ab}
	b = &memoryConn{Conn: br, writer: bw, readDirection: ab, writeDirection: ba}
	tb.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// Separate pipes let closing the writer deliver EOF without closing the reader.
// Each direction serializes deadline changes with closing either endpoint.
type memoryDirection struct {
	mu     sync.Mutex
	reader net.Conn
	writer net.Conn
}

func (d *memoryDirection) close(endpoint net.Conn) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	// net.Pipe.Close does not stop deadline timers, and deadlines cannot be
	// cleared after either endpoint closes. Clear both sides before closing.
	_ = d.reader.SetReadDeadline(time.Time{})
	_ = d.writer.SetWriteDeadline(time.Time{})
	return endpoint.Close()
}

type memoryConn struct {
	net.Conn
	writer         net.Conn
	readDirection  *memoryDirection
	writeDirection *memoryDirection
}

func (c *memoryConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *memoryConn) CloseWrite() error { return c.writeDirection.close(c.writer) }

func (c *memoryConn) Close() error {
	return errors.Join(c.readDirection.close(c.Conn), c.CloseWrite())
}

func (c *memoryConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *memoryConn) SetReadDeadline(t time.Time) error {
	c.readDirection.mu.Lock()
	defer c.readDirection.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *memoryConn) SetWriteDeadline(t time.Time) error {
	c.writeDirection.mu.Lock()
	defer c.writeDirection.mu.Unlock()
	return c.writer.SetWriteDeadline(t)
}
