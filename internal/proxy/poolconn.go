// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// poolConn tracks actual transport closure, not just the handler's lifetime:
// a half-closed upstream must not be handed to another request for reuse.
type poolConn struct {
	layer.Conn
	pool  *serverPool
	entry *poolEntry
	stop  func()
}

// Read reads server bytes and records EOF or fatal transport failures in the pool.
func (c *poolConn) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(buf)
	if errors.Is(err, io.EOF) {
		_ = c.halfClose(connection.CanRead)
	} else if fatalTransportError(err) {
		_ = c.Close()
	}
	return n, err
}

// Write writes server bytes and retires the connection after fatal transport failures.
func (c *poolConn) Write(buf []byte) (int, error) {
	n, err := c.Conn.Write(buf)
	if fatalTransportError(err) {
		_ = c.Close()
	}
	return n, err
}

// CloseWrite half-closes the transport and updates its pooled connection state.
func (c *poolConn) CloseWrite() error {
	err := c.Conn.CloseWrite()
	if fatalTransportError(err) {
		return errors.Join(err, c.Close())
	}
	if err != nil {
		return err
	}
	return c.halfClose(connection.CanWrite)
}

func (c *poolConn) halfClose(direction connection.State) error {
	c.entry.state.And(^uint32(direction))
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.pool.ctx), poolCleanupTimeout)
	defer cancel()
	err := c.pool.do(ctx, func(context.Context) error {
		c.entry.srv.State = connection.State(c.entry.state.Load())
		return nil
	})
	err = errors.Join(err, ctx.Err())
	if c.entry.state.Load() == uint32(connection.Closed) {
		return errors.Join(err, c.Close())
	}
	return err
}

// Close closes the transport and retires its pool entry with disconnection notification.
func (c *poolConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	err := c.Conn.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return errors.Join(err, c.pool.end(c.entry, nil))
}

func fatalTransportError(err error) bool {
	if err == nil {
		return false
	}
	if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
		// The next-layer selector interrupts reads with temporary deadlines.
		return false
	}
	return true
}
