// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layertest

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// MemoryPipe returns an in-memory connection pair with working half-close
// semantics and hang-detector deadlines. Both endpoints close in cleanup.
// Writes are synchronous, so fuzz targets can control read segmentation.
func MemoryPipe(tb testing.TB) (a, b layer.Conn) {
	tb.Helper()
	ar, bw := net.Pipe()
	br, aw := net.Pipe()
	a = &memoryConn{Conn: ar, writer: aw}
	b = &memoryConn{Conn: br, writer: bw}
	tb.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	for _, c := range []layer.Conn{a, b} {
		if err := c.SetDeadline(time.Now().Add(Timeout)); err != nil {
			fail(tb, "set memory pipe deadline", err)
		}
	}
	return a, b
}

// Separate pipes let closing the writer deliver EOF without closing the reader.
type memoryConn struct {
	net.Conn
	writer net.Conn
}

func (c *memoryConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *memoryConn) CloseWrite() error { return c.writer.Close() }

func (c *memoryConn) Close() error { return errors.Join(c.Conn.Close(), c.writer.Close()) }

func (c *memoryConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *memoryConn) SetWriteDeadline(t time.Time) error { return c.writer.SetWriteDeadline(t) }
