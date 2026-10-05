// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/options"
)

// ErrHalfCloseUnsupported is returned by CloseWrite on a client transport
// that cannot shut down its write side alone. The connection stays usable;
// a layer that needs half-close treats it like any other CloseWrite error.
var ErrHalfCloseUnsupported = errors.New("proxy: transport does not support half-close")

const defaultTCPTimeout = 600 * time.Second

// Config carries the shared dependencies of a [Handler].
type Config struct {
	// Manager is the addon dispatch domain hooks run in. Required.
	Manager *addon.Manager
	// Options are the proxy options layers read. Required.
	Options *options.Manager
	// Connections is the registry of live client connections. Required.
	Connections *Connections
	// Dialer opens server transports. Nil means a TCP dialer that uses the
	// server metadata's Sockname as the local address when it is set.
	Dialer layer.Dialer
	// HTTPFidelity is this proxy instance's head-byte normalisation
	// counter. Nil disables accounting.
	HTTPFidelity *http1.FidelityCounter
	// Logger is the base logger. Nil means [slog.Default].
	Logger *slog.Logger
}

// Handler serves accepted client connections: the counterpart of
// mitmproxy's ConnectionHandler (py:mitmproxy/proxy/server.py), shared by
// every connection of a proxy instance where upstream creates one handler
// object per connection. Each [Handler.Handle] call owns one client.
type Handler struct {
	manager     *addon.Manager
	options     *options.Manager
	connections *Connections
	dial        layer.Dialer
	fidelity    *http1.FidelityCounter
	logger      *slog.Logger
	clock       watchdogClock
}

// NewHandler validates cfg and returns a Handler.
func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Manager == nil || cfg.Options == nil || cfg.Connections == nil {
		return nil, errors.New("proxy: NewHandler requires Manager, Options and Connections")
	}
	h := &Handler{
		manager:     cfg.Manager,
		options:     cfg.Options,
		connections: cfg.Connections,
		dial:        cfg.Dialer,
		fidelity:    cfg.HTTPFidelity,
		logger:      cfg.Logger,
		clock:       wallClock{},
	}
	if h.dial == nil {
		h.dial = dialServer
	}
	if h.logger == nil {
		h.logger = slog.Default()
	}
	return h, nil
}

// Handle serves one accepted client connection until it ends: it fills the
// client metadata, fires client_connected and client_disconnected, builds
// the top layer from the mode's spec through [layer.Build] and runs it, and
// closes the client socket and every pooled server connection when the top
// layer returns. modeSpec is the full proxy mode specification the client
// connected to, stored verbatim as the client's proxy mode. An idle
// connection expires after the tcp_timeout option's seconds, counted
// outside hooks and interception waits.
//
// Handle returns nil when the connection ended ordinarily, the idle expiry
// and a client_connected handler's kill included, and an error only for a
// failure the mode server should log.
func (h *Handler) Handle(ctx context.Context, conn net.Conn, modeSpec string, top hookdata.LayerSpec) error {
	if conn == nil {
		return errors.New("proxy: Handle with a nil connection")
	}
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	raw := asLayerConn(conn)

	client := newHandledClient(conn, modeSpec)
	peer := formattedPeer(client)
	logger := h.logger.With("client", peer)
	watchdog := newWatchdog(h.timeout(), h.clock, func() {
		logger.Info("Closing connection due to inactivity: " + peer)
		cancel()
	})
	defer watchdog.close()
	// Cancellation must unblock layers sitting in reads on the client.
	closed := make(chan struct{})
	stopClose := context.AfterFunc(connCtx, func() { _ = raw.Close(); close(closed) })
	defer func() {
		if !stopClose() {
			<-closed
		}
	}()

	runner := &HookRunner{Manager: h.manager, Disarm: watchdog.disarm, Rearm: watchdog.rearm}
	dial := func(ctx context.Context, server *connection.Server) (layer.Conn, error) {
		conn, err := h.dial(ctx, server)
		if err != nil {
			return conn, err
		}
		return &activityConn{Conn: conn, watchdog: watchdog}, nil
	}
	pool := newServerPool(connCtx, client, dial, runner, h.manager.Do)
	queue := newInjectionQueue()
	c := &layer.Context{
		Data:         &hookdata.Context{Client: client, Server: connection.NewServer(nil), Options: h.options},
		Client:       Record(&activityConn{Conn: raw, watchdog: watchdog}),
		Record:       Record,
		Hooks:        runner,
		Pool:         pool,
		Inject:       queue.messages,
		NextLayer:    nextLayer,
		Do:           h.manager.Do,
		HTTPFidelity: h.fidelity,
		Logger:       logger,
	}
	id := client.ID
	entry := &liveConn{client: client, queue: queue, cancel: cancel, do: h.manager.Do}
	if err := h.connections.add(entry); err != nil {
		_ = raw.Close()
		return err
	}

	runErr := h.serve(connCtx, c, runner, client, top, logger)
	if ordinaryEnd(connCtx, runErr) {
		runErr = nil
	}

	// Stop accepting injection before disconnect hooks or pool joins. All
	// cleanup hooks run outside the canceled connection context.
	watchdog.close()
	queue.close()
	cancel()
	_ = raw.Close()
	_, hookErr := runner.FireFunc(context.WithoutCancel(ctx), func(context.Context) error {
		now := nowSeconds()
		client.TimestampEnd = &now
		client.State = connection.Closed
		return nil
	}, addon.ClientDisconnectedHook{Client: client})
	closeErr := pool.closeAll(context.WithoutCancel(ctx))
	h.connections.remove(id)
	return errors.Join(runErr, closeErr, hookErr)
}

// serve fires client_connected and runs the mode's top layer.
func (h *Handler) serve(ctx context.Context, c *layer.Context, runner *HookRunner, client *connection.Client, top hookdata.LayerSpec, logger *slog.Logger) error {
	if _, err := runner.Fire(ctx, addon.ClientConnectedHook{Client: client}); err != nil {
		return err
	}
	killed := false
	if err := h.manager.Do(ctx, func(context.Context) error {
		killed = client.Error != nil
		return nil
	}); err != nil {
		return err
	}
	if killed {
		logger.Info("client kill connection")
		return nil
	}
	topLayer, err := layer.Build(ctx, c, hookdata.LayerStack{top})
	if err != nil {
		return err
	}
	return topLayer.Run(ctx, c)
}

// Inject queues a cloned TCP message for its live flow's client connection.
// Flow metadata and message bytes are read under dispatch; ctx may carry a
// command's existing dispatch frame. Delivery never waits for the layer:
// ErrInjectionFull, ErrInjectionSize and ErrInjectionType propagate to the
// command caller, and ErrFlowNotLive reports a finished flow or connection.
func (h *Handler) Inject(ctx context.Context, injected layer.Injected) error {
	return h.manager.Do(ctx, func(context.Context) error {
		if injected.Flow == nil {
			return ErrFlowNotLive
		}
		f, ok := injected.Flow.(*flow.TCPFlow)
		if !ok {
			return ErrInjectionType
		}
		if f == nil || !f.Live || f.ClientConn == nil {
			return ErrFlowNotLive
		}
		entry := h.connections.lookup(f.ClientConn.ID)
		if entry == nil {
			return ErrFlowNotLive
		}
		if err := entry.queue.send(injected); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return ErrFlowNotLive
			}
			return err
		}
		return nil
	})
}

func (h *Handler) timeout() time.Duration {
	if h.options.Has("tcp_timeout") {
		return time.Duration(h.options.Int("tcp_timeout")) * time.Second
	}
	return defaultTCPTimeout
}

// newHandledClient fills the client metadata of an accepted connection as
// mitmproxy's LiveConnectionHandler does: open, started now, in the given
// mode. No handler can see the client before its first hook fires, so the
// writes need no dispatch hold.
func newHandledClient(conn net.Conn, modeSpec string) *connection.Client {
	var peer, local connection.Address
	if a := addressOf(conn.RemoteAddr()); a != nil {
		peer = *a
	}
	if a := addressOf(conn.LocalAddr()); a != nil {
		local = *a
	}
	client := connection.NewClient(peer, local, nowSeconds())
	client.State = connection.Open
	client.ProxyMode = modeSpec
	return client
}

func formattedPeer(client *connection.Client) string {
	if client.Peername == nil {
		return "<no address>"
	}
	return client.Peername.String()
}

// ordinaryEnd reports whether err is how a connection ends rather than a
// failure: the peer closed, the handler was cancelled (idle expiry,
// registry Close, server shutdown), or the transport went away under a
// layer.
func ordinaryEnd(ctx context.Context, err error) bool {
	if err == nil {
		return true
	}
	if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}

type closeWriter interface {
	CloseWrite() error
}

type halfCloseConn struct {
	net.Conn
	closeWrite func() error
}

func (c *halfCloseConn) CloseWrite() error { return c.closeWrite() }

type noHalfCloseConn struct {
	net.Conn
}

func (*noHalfCloseConn) CloseWrite() error { return ErrHalfCloseUnsupported }

// asLayerConn adapts an accepted socket to [layer.Conn]. A transport
// without its own half-close support reports [ErrHalfCloseUnsupported]
// from CloseWrite instead of pretending by closing both directions.
func asLayerConn(conn net.Conn) layer.Conn {
	if c, ok := conn.(layer.Conn); ok {
		return c
	}
	if c, ok := conn.(closeWriter); ok {
		return &halfCloseConn{Conn: conn, closeWrite: c.CloseWrite}
	}
	return &noHalfCloseConn{Conn: conn}
}

// dialServer is the default dialer: TCP to the server's address, from the
// Sockname the connect_addr option selected when one is set.
func dialServer(ctx context.Context, srv *connection.Server) (layer.Conn, error) {
	if srv.Address == nil || srv.Address.Host == "" {
		return nil, errors.New("proxy: cannot open connection, no hostname given")
	}
	if srv.TransportProtocol != connection.TCP {
		return nil, fmt.Errorf("proxy: transport protocol %q is not supported yet", srv.TransportProtocol)
	}
	dialer := net.Dialer{}
	if srv.Sockname != nil && srv.Sockname.Host != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(srv.Sockname.Host)}
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(srv.Address.Host, strconv.Itoa(srv.Address.Port)))
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}
