// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

type layerClock struct{ watchdogClock }

func (c layerClock) Now() time.Time                                  { return c.now() }
func (c layerClock) AfterFunc(d time.Duration, f func()) func() bool { return c.afterFunc(d, f).Stop }

// HandlePackets owns an accepted UDP tuple until its top layer finishes.
// It preserves packet boundaries, closes only this tuple and its origin sockets,
// and fires the same connection lifecycle hooks as Handle. An idle tuple expires
// at UDPIdleTimeout; replay of recorded packets does not extend its lifetime.
func (h *Handler) HandlePackets(ctx context.Context, conn *packettransport.TupleConn, modeSpec string, top hookdata.LayerSpec) error {
	if conn == nil {
		return errors.New("proxy: HandlePackets with a nil connection")
	}
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := connection.NewClient(*addressOf(conn.RemoteAddr()), *addressOf(conn.LocalAddr()), nowSeconds())
	client.TransportProtocol, client.State, client.ProxyMode = connection.UDP, connection.Open, modeSpec
	peer := formattedPeer(client)
	logger := h.logger.With("client", peer)
	watchdog := newPacketWatchdog(h.clock, func() { logger.Info("Closing connection due to inactivity: " + peer); cancel() })
	defer watchdog.close()
	closed := make(chan struct{})
	stopClose := context.AfterFunc(connCtx, func() { _ = conn.Close(); close(closed) })
	defer func() {
		if !stopClose() {
			<-closed
		}
	}()
	runner := &HookRunner{Manager: h.manager, Disarm: watchdog.disarm, Rearm: watchdog.rearm}
	servers := &packetServers{ctx: connCtx, client: client, hooks: runner, do: h.manager.Do, watchdog: watchdog}
	queue := newInjectionQueue()
	server := connection.NewServer(nil)
	server.TransportProtocol = connection.UDP
	c := &layer.Context{
		Data:          &hookdata.Context{Client: client, Server: server, Options: h.options},
		ClientPackets: RecordPackets(&activityPackets{PacketTransport: conn, watchdog: watchdog}),
		RecordPackets: RecordPackets,
		OpenPackets:   servers.open,
		Clock:         layerClock{h.clock},
		Hooks:         runner,
		Inject:        queue.messages,
		NextLayer:     nextLayer,
		Do:            h.manager.Do,
		Logger:        logger,
	}
	entry := &liveConn{client: client, queue: queue, cancel: cancel, do: h.manager.Do}
	if err := h.connections.add(entry); err != nil {
		_ = conn.Close()
		return err
	}
	runErr := h.serve(connCtx, c, runner, client, top, logger)
	if !errors.Is(runErr, layer.ErrPacketOverflow) && ordinaryEnd(connCtx, runErr) {
		runErr = nil
	}
	watchdog.close()
	queue.close()
	cancel()
	_ = conn.Close()
	_, hookErr := runner.FireFunc(context.WithoutCancel(ctx), func(context.Context) error {
		now := nowSeconds()
		client.TimestampEnd, client.State = &now, connection.Closed
		return nil
	}, addon.ClientDisconnectedHook{Client: client})
	closeErr := servers.close()
	h.connections.remove(client.ID)
	return errors.Join(runErr, hookErr, closeErr)
}

type packetServer struct {
	transport layer.PacketTransport
	server    *connection.Server
}

// Packet opens have no stream pooling or half-close operations. The registry
// only joins pending opens and closes origins when their owning client ends.
// Dispatch is never acquired while mu is held.
type packetServers struct {
	ctx      context.Context
	client   *connection.Client
	hooks    layer.Hooks
	do       func(context.Context, func(context.Context) error) error
	watchdog *watchdog
	mu       sync.Mutex
	workers  sync.WaitGroup
	closed   bool
	entries  []packetServer
}

func (p *packetServers) open(ctx context.Context, server *connection.Server) (layer.PacketTransport, *connection.Server, error) {
	if server == nil {
		return nil, nil, errors.New("proxy: OpenPackets with a nil server")
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	p.workers.Add(1)
	p.mu.Unlock()
	defer p.workers.Done()
	openCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	data := &hookdata.ServerConnection{Client: p.client, Server: server}
	failed := func(cause error) (layer.PacketTransport, *connection.Server, error) {
		_, hookErr := p.hooks.FireFunc(context.WithoutCancel(p.ctx), func(context.Context) error {
			if server.Error == nil {
				reason := cause.Error()
				server.Error = &reason
			}
			server.State = connection.Closed
			return nil
		}, addon.ServerConnectErrorHook{Data: data})
		return nil, nil, errors.Join(cause, hookErr)
	}
	if _, err := p.hooks.Fire(openCtx, addon.ServerConnectHook{Data: data}); err != nil {
		return failed(err)
	}
	var snapshot *connection.Server
	if err := p.do(openCtx, func(context.Context) error {
		if server.Error != nil {
			return fmt.Errorf("proxy: connection killed: %s", *server.Error)
		}
		now := nowSeconds()
		server.TimestampStart = &now
		snapshot = server.Clone()
		return nil
	}); err != nil {
		return failed(err)
	}
	// The socket lifetime follows the client, not the short-lived open call.
	raw, err := dialPacketServer(openCtx, p.ctx, snapshot, net.Dialer{})
	if err != nil {
		return failed(err)
	}
	if err := openCtx.Err(); err != nil {
		_ = raw.Close()
		return failed(err)
	}
	peer, local := addressOf(raw.RemoteAddr()), addressOf(raw.LocalAddr())
	_, err = p.hooks.FireFunc(openCtx, func(context.Context) error {
		now := nowSeconds()
		server.TimestampTCPSetup, server.State = &now, connection.Open
		server.Peername, server.Sockname = peer, local
		return nil
	}, addon.ServerConnectedHook{Data: data})
	p.mu.Lock()
	closed := p.closed
	if !closed {
		p.entries = append(p.entries, packetServer{transport: raw, server: server})
	}
	p.mu.Unlock()
	if closed || err != nil {
		_ = raw.Close()
		if closed {
			err = errors.Join(err, net.ErrClosed)
		}
		return nil, nil, err
	}
	return &activityPackets{PacketTransport: raw, watchdog: p.watchdog}, server, nil
}

func (p *packetServers) close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.workers.Wait()
	var errs []error
	for _, entry := range p.entries {
		_ = entry.transport.Close()
		_, err := p.hooks.FireFunc(context.WithoutCancel(p.ctx), func(context.Context) error {
			now := nowSeconds()
			entry.server.TimestampEnd, entry.server.State = &now, connection.Closed
			return nil
		}, addon.ServerDisconnectedHook{Data: &hookdata.ServerConnection{Client: p.client, Server: entry.server}})
		errs = append(errs, err)
	}
	p.entries = nil
	return errors.Join(errs...)
}

type connectedPackets struct {
	*net.UDPConn
	ctx    context.Context
	cancel context.CancelFunc
	stop   func() bool
	readMu sync.Mutex
	buffer [layer.MaxUDPPacketBytes + 1]byte
}

func (c *connectedPackets) Context() context.Context { return c.ctx }

func (c *connectedPackets) Close() error {
	c.stop()
	err := c.UDPConn.Close()
	c.cancel()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (c *connectedPackets) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.Read(c.buffer[:])
	if n > layer.MaxUDPPacketBytes {
		_ = c.Close()
		return 0, nil, layer.ErrPacketOverflow
	}
	if err != nil {
		return 0, nil, err
	}
	return copy(p, c.buffer[:n]), c.RemoteAddr(), nil
}

func (c *connectedPackets) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr != nil && addr.String() != c.RemoteAddr().String() {
		return 0, errors.New("proxy: packet peer differs from fixed origin")
	}
	if len(p) > layer.MaxUDPPacketBytes {
		_ = c.Close()
		return 0, layer.ErrPacketOverflow
	}
	return c.Write(p)
}

func dialPacketServer(ctx, lifetime context.Context, srv *connection.Server, dialer net.Dialer) (*connectedPackets, error) {
	if srv.Address == nil || srv.Address.Host == "" {
		return nil, errors.New("proxy: cannot open connection, no hostname given")
	}
	if srv.TransportProtocol != connection.UDP {
		return nil, fmt.Errorf("proxy: packet dial requires UDP, got %q", srv.TransportProtocol)
	}
	if srv.Sockname != nil {
		local := &net.UDPAddr{Port: srv.Sockname.Port}
		if srv.Sockname.Host != "" {
			source, err := netip.ParseAddr(srv.Sockname.Host)
			if err != nil {
				return nil, fmt.Errorf("proxy: invalid source address %q: %w", srv.Sockname.Host, err)
			}
			local.IP, local.Zone = source.AsSlice(), source.Zone()
		}
		if srv.Sockname.Scope != nil && srv.Sockname.Scope.ScopeID != 0 {
			local.Zone = strconv.FormatUint(uint64(srv.Sockname.Scope.ScopeID), 10)
		}
		dialer.LocalAddr = local
	}
	raw, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(srv.Address.Host, strconv.Itoa(srv.Address.Port)))
	if err != nil {
		return nil, err
	}
	udpConn := raw.(*net.UDPConn)
	if err := packettransport.ConfigureSocketBuffers(udpConn); err != nil {
		_ = raw.Close()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(lifetime)
	c := &connectedPackets{UDPConn: udpConn, ctx: lifetime, cancel: cancel}
	c.stop = context.AfterFunc(lifetime, func() { _ = raw.Close() })
	return c, nil
}
