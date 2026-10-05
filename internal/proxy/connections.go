// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/zchee/mitmproxy-go/connection"
)

// ErrFlowNotLive means an injection's flow does not belong to a connection
// this registry currently serves, as mitmproxy reports when inject_event
// finds no handler for the flow's client (py:mitmproxy/addons/proxyserver.py).
var ErrFlowNotLive = errors.New("proxy: flow is not from a live connection")

// liveConn is one registered client connection: what injection routing and
// connection snapshots need, never the sockets themselves.
type liveConn struct {
	client *connection.Client
	queue  *injectionQueue
	cancel context.CancelFunc
	do     func(context.Context, func(context.Context) error) error
}

// Connections tracks the live client connections of the handlers that share
// it, keyed by client connection ID, as mitmproxy's ServerManager keeps its
// connections map (py:mitmproxy/proxy/mode_servers.py). The zero value is
// ready to use. [Handler.Handle] registers and removes connections; the
// proxyserver addon reads it for active_connections and inject.tcp.
type Connections struct {
	mu     sync.Mutex
	conns  map[string]*liveConn
	closed bool
}

// Len returns the number of live client connections.
func (c *Connections) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

// Snapshot returns a deep copy of every live client connection's metadata,
// each cloned under a hold of the dispatch lock so a concurrent hook's
// writes are never observed half-made. ctx may carry a current dispatch
// frame; without one the lock is taken per connection.
func (c *Connections) Snapshot(ctx context.Context) ([]*connection.Client, error) {
	c.mu.Lock()
	entries := make([]*liveConn, 0, len(c.conns))
	for _, entry := range c.conns {
		entries = append(entries, entry)
	}
	c.mu.Unlock()
	clients := make([]*connection.Client, 0, len(entries))
	for _, entry := range entries {
		if err := entry.do(ctx, func(context.Context) error {
			clients = append(clients, entry.client.Clone())
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return clients, nil
}

// Close cancels every live connection and refuses new registrations. It
// never waits for connection goroutines: each handler tears its connection
// down on its own, under the dispatch lock where its hooks need it.
func (c *Connections) Close() {
	c.mu.Lock()
	c.closed = true
	entries := make([]*liveConn, 0, len(c.conns))
	for _, entry := range c.conns {
		entries = append(entries, entry)
	}
	c.mu.Unlock()
	for _, entry := range entries {
		entry.cancel()
	}
}

func (c *Connections) add(entry *liveConn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.conns == nil {
		c.conns = make(map[string]*liveConn)
	}
	if _, taken := c.conns[entry.client.ID]; taken {
		return errors.New("proxy: a connection with this client ID is already registered")
	}
	c.conns[entry.client.ID] = entry
	return nil
}

func (c *Connections) remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.conns, id)
}

func (c *Connections) lookup(id string) *liveConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conns[id]
}
