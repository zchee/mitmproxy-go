// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package layer defines the contract between the proxy's connection
// handler and its protocol layers: what a layer is, how it is built, how it
// reads and writes connections, and how it fires hooks. Layer packages
// import this package; the machinery that drives them lives in
// internal/proxy.
//
// Where mitmproxy's layers are sans-io state machines exchanging commands
// and events on one event loop (py:mitmproxy/proxy/layer.py), a layer here
// is a function running on the connection's goroutines over blocking
// connections. The rules below keep the two models equivalent for
// handlers.
//
// # Rules every layer must follow
//
//   - Connections: a layer reads and writes the conns it is given, may
//     CloseWrite them, and never closes a conn it did not open. The
//     connection handler closes the client conn and every pooled server
//     conn when the top layer returns.
//   - Half-close: CloseWrite sends the transport's end-of-stream (a FIN on
//     TCP). A TLS conn's CloseWrite sends close_notify and then a FIN on
//     the underlying conn, because mitmproxy half-closes TLS with a bare
//     FIN (py:mitmproxy/proxy/layers/tls.py). After CloseWrite a layer may
//     keep reading; it treats a read error or EOF in the other direction
//     as that direction's close.
//   - Hooks: a layer fires hooks only through [Hooks], never by calling
//     the addon manager directly: the runner disarms the connection's idle
//     watchdog and handles interception, which a direct call would skip.
//     Hooks may be fired anywhere on the layer's own goroutines, but never
//     while holding another flow's turn: a relay serialises its two
//     directions through each hook.
//   - Flows: a layer writes a flow field that handlers can see only in the
//     prepare step of [Hooks.FireFunc] (which runs it and the hook in one
//     hold of the dispatch lock) or inside master.Do. Between hooks it
//     keeps what it has read (a body, a TCP chunk) in its own variables
//     and stores it into the flow in the next hook's prepare. What it
//     sends after a hook it reads only from the [Snapshot] the runner
//     returns, never from the flow, because handlers and master.Do
//     callbacks own the flow outside the hold.
//   - Blocking: a layer never blocks on network I/O, a lock or another
//     goroutine while inside a prepare or finish callback, and never
//     waits for another connection's goroutines at all.
package layer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
)

// Layer is one protocol layer of a connection: the counterpart of
// mitmproxy's Layer (py:mitmproxy/proxy/layer.py), run as a function
// instead of a state machine.
type Layer interface {
	// Run handles the connection until the layer is done: the connection
	// ended, the layer handed over to a child whose Run returned, or an
	// error made the connection unusable. ctx is the connection's context;
	// its cancellation means the client handler is shutting down. Run is
	// called at most once.
	Run(ctx context.Context, c *Context) error

	// Kind returns the layer's kind. The values in [Context.Data]'s Layers
	// are inspected by it, for example by the tlsconfig addon testing for
	// the secure-web-proxy stack.
	Kind() hookdata.LayerKind
}

// Constructor builds a layer from its spec. child is the layer below it in
// the stack, already built, or nil when the spec is the innermost of its
// stack; a layer whose protocol nests another layer and finds child nil
// asks [Next] when the handover point is reached, as mitmproxy's
// default NextLayer child does. A Constructor runs under the dispatch lock,
// must not wait for I/O, and must not append to [Context.Data]'s Layers;
// [Build] publishes the completed stack.
type Constructor func(c *Context, spec hookdata.LayerSpec, child Layer) (Layer, error)

// registry maps layer kinds to constructors. Layer packages fill it from
// init, so the proxy and the nextlayer addon import no concrete layer
// package.
var registry sync.Map // hookdata.LayerKind -> Constructor

// Register registers the constructor for kind. Layer packages call it from
// init; registering a kind twice or a nil constructor panics.
func Register(kind hookdata.LayerKind, ctor Constructor) {
	if ctor == nil {
		panic(fmt.Sprintf("layer: Register(%q) with a nil constructor", kind))
	}
	if _, loaded := registry.LoadOrStore(kind, ctor); loaded {
		panic(fmt.Sprintf("layer: Register(%q) called twice", kind))
	}
}

// Build constructs stack from innermost to outermost, passing each child to
// its parent, then publishes the whole stack in c.Data.Layers outermost first.
// It uses c.Do to hold the dispatch lock across construction and publication;
// pass the current frame in ctx when already inside a hold. A failed build
// leaves c.Data.Layers unchanged. Constructors must obey [Constructor].
// Mode layers are permitted only as the single initial layer.
func Build(ctx context.Context, c *Context, stack hookdata.LayerStack) (Layer, error) {
	if c == nil || c.Data == nil || c.Do == nil {
		return nil, fmt.Errorf("layer: Build requires a context with Data and Do")
	}
	if len(stack) == 0 {
		return nil, fmt.Errorf("layer: Build with an empty stack")
	}
	var outer Layer
	err := c.Do(ctx, func(context.Context) error {
		built := make([]Layer, len(stack))
		var child Layer
		for i := len(stack) - 1; i >= 0; i-- {
			spec := stack[i]
			if spec.HTTPMode != "" && spec.Kind != hookdata.LayerHTTP || spec.Ignore && spec.Kind != hookdata.LayerTCP {
				return fmt.Errorf("layer: incompatible settings for %q", spec.Kind)
			}
			if spec.Kind == hookdata.LayerHTTP && spec.HTTPMode != hookdata.HTTPModeRegular && spec.HTTPMode != hookdata.HTTPModeUpstream && spec.HTTPMode != hookdata.HTTPModeTransparent {
				return fmt.Errorf("layer: invalid HTTP mode %q", spec.HTTPMode)
			}
			switch spec.Kind {
			case hookdata.LayerRegular, hookdata.LayerReverse, hookdata.LayerUpstream:
				if len(c.Data.Layers) != 0 || len(stack) != 1 {
					return fmt.Errorf("layer: mode %q is only valid as the initial top layer", spec.Kind)
				}
			}
			v, ok := registry.Load(spec.Kind)
			if !ok {
				return fmt.Errorf("layer: no layer registered for kind %q", spec.Kind)
			}
			l, err := v.(Constructor)(c, spec, child)
			if err != nil {
				return fmt.Errorf("layer: building %q: %w", spec.Kind, err)
			}
			if l == nil || l.Kind() != spec.Kind {
				return fmt.Errorf("layer: constructor for %q returned an invalid layer", spec.Kind)
			}
			built[i], child = l, l
		}
		for _, l := range built {
			c.Data.Layers = append(c.Data.Layers, l)
		}
		outer = built[0]
		return nil
	})
	return outer, err
}

// Next asks the next_layer hook until a handler has decided on a stack,
// builds the stack through [Build] and returns its outermost layer. The
// connection handler wires it into [Context.NextLayer]; it is also callable
// from inside a running layer, for example to decide the child of a
// CONNECT tunnel, as mitmproxy creates a NextLayer there
// (py:mitmproxy/proxy/layers/http). It asks on every client or server
// read, never at connection start: mitmproxy's mode servers replace the
// initial ask-on-start NextLayer with the mode's top layer, and every
// later NextLayer is created without ask_on_start
// (py:mitmproxy/proxy/mode_servers.py, py:mitmproxy/proxy/layers/modes.py).
// A client close before a decision is an error that closes the connection
// (py:mitmproxy/proxy/layer.py NextLayer._handle_event); the bytes read
// while deciding reach the chosen layer through the recording conn's
// replay.
func Next(ctx context.Context, c *Context) (Layer, error) {
	if c == nil || c.NextLayer == nil {
		return nil, fmt.Errorf("layer: no next-layer selector configured")
	}
	return c.NextLayer(ctx, c)
}

// Conn is a connection a layer reads and writes: a [net.Conn] that can be
// half-closed. See the package rules for who closes a Conn.
type Conn interface {
	net.Conn

	// CloseWrite sends the transport's end-of-stream and shuts down the
	// write side; reads stay possible. For TLS it sends close_notify and
	// then a FIN on the conn below.
	CloseWrite() error
}

// Injected is a message an addon injected into a live flow, for example
// through the inject.tcp command. The proxy delivers it to the layer that
// owns the flow through [Context.Inject]; the layer selects on that
// channel next to its reads, sends the message to the named peer and
// records it on the flow like a received message
// (py:mitmproxy/proxy/events.py MessageInjected).
type Injected struct {
	// Flow is the flow the message belongs to.
	Flow flow.Flow
	// Message is the protocol message to inject, such as *tcp.Message.
	Message any
}

// Context carries everything a layer needs: the hook-visible connection
// context, the client conn, the hook runner, the server pool, the
// injection channel, the next-layer loop and the connection's logger. The
// connection handler creates one per client connection; every layer of the
// connection shares it.
type Context struct {
	// Data is the hook-visible context of the connection: the client and
	// server connection metadata, the options, and Layers, the built
	// [Layer] values of the stack, outermost first, which addons such as
	// tlsconfig inspect by Kind.
	Data *hookdata.Context

	// Client is the client connection. It records until the first layer
	// decision so that bytes read while sniffing replay into the chosen
	// layer; see [Recorder].
	Client Recorder

	// Hooks fires hooks for this connection. Layers use it for every
	// hook; see the package rules.
	Hooks Hooks

	// Pool opens server connections; see [ServerPool].
	Pool ServerPool

	// Inject delivers messages addons injected into this connection's
	// flows. The layer that owns the current flow selects on it next to
	// its reads. The channel is bounded and the sender does not block:
	// injection into a connection that never drains it fails rather than
	// stalling the dispatch lock.
	Inject <-chan Injected

	// NextLayer implements [Next] for the current transport and metadata.
	// It runs outside the dispatch lock and may wait for network reads.
	NextLayer func(context.Context, *Context) (Layer, error)

	// Do runs bounded metadata reads or writes under the dispatch lock,
	// re-entering when ctx carries a current frame. Use FireFunc instead
	// when a flow mutation must atomically precede a hook. The callback
	// must not wait for network I/O, another lock, or a goroutine.
	Do func(context.Context, func(context.Context) error) error

	// Server is the current server-side transport, when already open.
	// A layer that wraps it must preserve buffered bytes through a Recorder.
	// Its metadata stays in Data.Server and is read or written only in Do.
	Server Recorder

	// Logger is the connection's logger, prefixed with the client address
	// like mitmproxy's log_prefix (py:mitmproxy/proxy/mode_servers.py).
	Logger *slog.Logger
}

// ServerPool opens connections to servers, per client connection, as
// mitmproxy's HttpLayer holds its connection pool per client
// (py:mitmproxy/proxy/layers/http). The connection handler owns the pool
// and closes every pooled conn when the top layer returns.
//
// Open fires the connection lifecycle hooks as mitmproxy's server does
// (py:mitmproxy/proxy/server.py open_connection): server_connect first (a
// handler that sets srv.Error kills the connection: Open fires
// server_connect_error and fails); then it dials outside the dispatch
// lock, through the pool's dialer (injectable for tests), with the
// connect_addr option as the source address; then server_connected on
// success or server_connect_error on failure; and server_disconnected
// later, when the connection ends. On success srv's state, peername,
// sockname and timestamps are filled in the hooks' prepare steps.
//
// With reuse true, Open may return an existing open connection whose key
// (address, tls, via, transport protocol, SNI) equals srv's instead of
// dialing. The returned [connection.Server] is the one actually in use:
// srv itself when a new connection was dialed, the pooled connection's
// server when reuse matched one. Establishment is single-flight per key:
// concurrent Opens for one key wait, outside the dispatch lock, for the
// first dial instead of dialing again — except that a waiter that needs
// HTTP/2 re-dials with reuse false when the established connection did
// not negotiate h2, instead of joining it (as in
// py:mitmproxy/proxy/layers/http/__init__.py). Setup, including TLS and
// CONNECT, is part of the same single flight as dialing; no waiter sees a
// connection until setup has finished.
type ServerPool interface {
	// Open returns the transport and the metadata of the actual connection.
	Open(ctx context.Context, srv *connection.Server, opts OpenOptions) (Conn, *connection.Server, error)
	// Upgrade applies setup to an already open raw connection exactly once.
	// Concurrent callers wait for the same result outside the dispatch lock.
	Upgrade(ctx context.Context, srv *connection.Server, setup func(context.Context, Conn, *connection.Server) (Conn, error)) (Conn, *connection.Server, error)
	// Lookup finds an established transport by metadata identity, without
	// dialing or waiting. It is safe to call concurrently with Open.
	Lookup(srv *connection.Server) (Conn, bool)
}

// OpenOptions controls reuse and setup of a server connection.
type OpenOptions struct {
	// Reuse permits reuse of an established connection with the same key.
	Reuse bool
	// Setup wraps the connected transport, for example with TLS or CONNECT.
	// It runs outside the dispatch lock and fires hooks through Hooks. On
	// failure the pool closes the connection. A nil function leaves it raw.
	Setup func(context.Context, Conn, *connection.Server) (Conn, error)
}

// Dialer opens a socket using a private snapshot of server metadata,
// including Sockname when the connect_addr option selected a source address.
// It must honor ctx cancellation. The pool owns and closes the returned conn.
type Dialer func(ctx context.Context, server *connection.Server) (Conn, error)

// Recorder is a [Conn] that can record what is read from it and replay it,
// so that bytes consumed while sniffing (the next-layer loop, the TLS
// ClientHello reader) reach the chosen layer unchanged, and bytes examined
// with Peek are not consumed at all. Its reads are not safe for concurrent
// use; one goroutine reads at a time, as with a [bufio.Reader].
type Recorder interface {
	Conn

	// Buffered returns the bytes available to the next Read without socket
	// I/O. While recording this excludes bytes already consumed; after
	// StopRecording it includes all recorded bytes not yet replayed.
	Buffered() int

	// Peek returns the next n bytes without consuming them, reading from
	// the socket as needed. The returned slice is valid until the next
	// read and may return fewer than n bytes with the error that stopped
	// it. Negative or oversized requests return an error, not a panic.
	// Recording and lookahead are bounded; stop recording before reading
	// application bodies that may exceed the transport's recording limit.
	Peek(n int) ([]byte, error)

	// StopRecording stops recording and rewinds: subsequent reads replay
	// every byte consumed while recording, in order, exactly once, then
	// peeked-but-unconsumed bytes, then the socket. Recording cannot be
	// restarted. Calling it again is a no-op.
	StopRecording()
}

// Hooks fires hooks for one connection. The runner, not the layer, holds
// the two responsibilities a direct addon.Manager call would miss: it
// disarms this connection's idle watchdog from before it waits for the
// dispatch lock until an intercepted flow's wait ends
// (py:mitmproxy/proxy/mode_servers.py, py:mitmproxy/proxy/server.py), and
// for a hook that carries a flow it waits for the flow to be resumed, with
// the stream's ctx, after the lock is released, so that a disconnect
// cancels the wait.
//
// Both methods return a [Snapshot] of the hook's flow, taken under a hold
// of the dispatch lock: in the same hold as the hook when the flow was not
// intercepted, otherwise under a fresh hold after the flow was resumed. A
// layer reads what it will send after the hook (the TCP content as the
// handlers left it, the HTTP response) only from that snapshot, never from
// the flow: outside a hold the flow belongs to handlers and master.Do
// callbacks. The snapshot is nil for a hook that carries no flow.
//
// Fire and FireFunc must be called with a context that does not carry a
// dispatch frame (never from inside a hook or a master.Do callback):
// waiting for an intercepted flow under the lock would deadlock the
// dispatch domain.
type Hooks interface {
	// Fire dispatches hook and update as addon.Manager.Hook does, with the
	// runner duties above.
	Fire(ctx context.Context, hook addon.Hook) (*Snapshot, error)

	// FireFunc is Fire with a prepare step: prepare, the hook chain and
	// update run in one hold of the dispatch lock, at the same depth as
	// Fire's dispatch, so a layer stores what it has read into the flow
	// and fires the hook on that state atomically while handlers keep
	// addon.Concurrent. prepare runs as a synchronous dispatch:
	// addon.Concurrent called from it returns an error wrapping
	// addon.ErrSyncContext. A prepare error skips the hook and is
	// returned.
	FireFunc(ctx context.Context, prepare func(context.Context) error, hook addon.Hook) (*Snapshot, error)
}
