// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/internal/netstack"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// The process-wide frontend reservation never owns the daemon. Its addon owner
// retains the daemon when interception is disabled between frontend instances.
var currentLocal atomic.Pointer[Instance]

type localSource struct {
	ctx         context.Context
	cancel      context.CancelFunc
	redirector  local.Redirector
	stack       *netstack.Stack
	once        sync.Once
	readers     sync.WaitGroup
	handlers    sync.WaitGroup
	failure     chan error
	monitorDone chan struct{}
	err         error
}

func (s *localSource) Close() error {
	s.once.Do(func() {
		s.cancel()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), 5*time.Second)
		defer cancel()
		interceptErr := s.redirector.SetIntercept(ctx, "")
		s.readers.Wait()
		var stackErr error
		if s.stack != nil {
			stackErr = s.stack.Close()
		}
		s.handlers.Wait()
		s.err = errors.Join(interceptErr, stackErr)
	})
	return s.err
}

func (s *localSource) fail(err error) {
	if s.ctx.Err() == nil {
		select {
		case s.failure <- err:
		default:
		}
	}
}

func (i *Instance) startLocal(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		i.state.Store(&instanceState{err: err})
		return err
	}
	if currentLocal.Load() == i && i.state.Load().local != nil {
		return nil
	}
	if !currentLocal.CompareAndSwap(nil, i) {
		err := errors.New("Cannot spawn more than one local redirector.") //nolint:staticcheck // Preserve upstream's singleton frontend diagnostic.
		i.state.Store(&instanceState{err: err})
		return err
	}
	fail := func(err error) error {
		currentLocal.CompareAndSwap(i, nil)
		i.state.Store(&instanceState{err: err})
		return err
	}
	if i.redirector == nil {
		return fail(errors.New("modeserver: local mode requires a process-owned redirector"))
	}
	if err := i.redirector.Launch(ctx); err != nil {
		return fail(err)
	}
	lifetime, cancel := context.WithCancel(ctx)
	source := &localSource{ctx: lifetime, cancel: cancel, redirector: i.redirector, failure: make(chan error, 1), monitorDone: make(chan struct{})}
	streams, streamMode := i.redirector.(local.StreamRedirector)
	if !streamMode {
		var err error
		source.stack, err = netstack.New(lifetime)
		if err != nil {
			cancel()
			return fail(err)
		}
	}
	spec := i.mode.Common().Data
	if spec == "" {
		spec = "!" + strconv.Itoa(os.Getpid())
	}
	if err := i.redirector.SetIntercept(ctx, spec); err != nil {
		cancel()
		if source.stack != nil {
			_ = source.stack.Close()
		}
		return fail(err)
	}
	state := &instanceState{local: source}
	i.state.Store(state)
	if streamMode {
		source.readers.Go(func() { i.readLocalTCP(source, streams) })
		source.readers.Go(func() { i.readLocalUDP(source, streams) })
	} else {
		source.readers.Go(func() { i.readLocalPackets(source) })
		source.readers.Go(func() { i.writeLocalPackets(source) })
		source.readers.Go(func() { i.acceptLocalPackets(source) })
	}
	go func() {
		var failure error
		select {
		case failure = <-source.failure:
		case <-lifetime.Done():
		}
		err := errors.Join(failure, source.Close())
		i.state.CompareAndSwap(state, &instanceState{err: err})
		currentLocal.CompareAndSwap(i, nil)
		close(source.monitorDone)
	}()
	i.logger.Info(i.mode.Description() + " started.")
	return nil
}

func (i *Instance) readLocalPackets(s *localSource) {
	for {
		packet, err := s.redirector.ReadPacket(s.ctx)
		if err != nil {
			s.fail(err)
			return
		}
		if packet == nil {
			s.fail(errors.New("local redirector returned a nil packet"))
			return
		}
		err = s.stack.Inject(packet.Data, localExtra(packet.TunnelInfo))
		if errors.Is(err, netstack.ErrQueueFull) || errors.Is(err, netstack.ErrInvalidPacket) {
			continue
		}
		if err != nil {
			s.fail(err)
			return
		}
	}
}

func (i *Instance) writeLocalPackets(s *localSource) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case packet, ok := <-s.stack.Outbound():
			if !ok {
				s.fail(net.ErrClosed)
				return
			}
			if err := s.redirector.WritePacket(s.ctx, &local.Packet{Data: packet}); err != nil {
				s.fail(err)
				return
			}
		}
	}
}

func (i *Instance) acceptLocalPackets(s *localSource) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case conn, ok := <-s.stack.TCPConns():
			if !ok {
				return
			}
			i.handleLocalTCP(s, conn)
		case conn, ok := <-s.stack.UDPConns():
			if !ok {
				return
			}
			i.handleLocalUDP(s, conn)
		}
	}
}

func (i *Instance) handleLocalTCP(s *localSource, conn net.Conn) {
	if admitted, _ := i.limiter.acquire(); !admitted {
		_ = conn.Close()
		return
	}
	s.handlers.Go(func() {
		defer i.limiter.release()
		if err := i.handler.Handle(s.ctx, conn, i.mode.String(), i.top); err != nil {
			i.logger.Error("Handling local TCP connection", "error", err)
		}
	})
}

func (i *Instance) handleLocalUDP(s *localSource, conn layer.PacketTransport) {
	if admitted, _ := i.limiter.acquire(); !admitted {
		_ = conn.Close()
		return
	}
	s.handlers.Go(func() {
		defer i.limiter.release()
		if err := i.handler.HandlePackets(s.ctx, conn, i.mode.String(), i.top); err != nil {
			i.logger.Error("Handling local UDP connection", "error", err)
		}
	})
}

func (i *Instance) readLocalTCP(s *localSource, streams local.StreamRedirector) {
	for {
		conn, flow, err := streams.AcceptTCP(s.ctx)
		if err != nil {
			s.fail(err)
			return
		}
		if flow == nil || flow.RemoteAddress == nil {
			_ = conn.Close()
			s.fail(errors.New("local TCP flow has no destination"))
			return
		}
		info := localExtra(flow.TunnelInfo)
		info["remote_endpoint"] = net.JoinHostPort(flow.RemoteAddress.Host, strconv.FormatUint(uint64(flow.RemoteAddress.Port), 10))
		info["transport_protocol"] = connection.TCP
		i.handleLocalTCP(s, &localStream{Conn: conn, info: info})
	}
}

func (i *Instance) readLocalUDP(s *localSource, streams local.StreamRedirector) {
	for {
		conn, flow, err := streams.AcceptUDP(s.ctx)
		if err != nil {
			s.fail(err)
			return
		}
		if flow == nil || flow.LocalAddress == nil {
			_ = conn.Close()
			s.fail(errors.New("local UDP flow has no source"))
			return
		}
		peer, err := netip.ParseAddrPort(net.JoinHostPort(flow.LocalAddress.Host, strconv.FormatUint(uint64(flow.LocalAddress.Port), 10)))
		if err != nil {
			_ = conn.Close()
			s.fail(err)
			return
		}
		info := localExtra(flow.TunnelInfo)
		info["remote_endpoint"] = conn.RemoteAddr().String()
		info["original_src"] = peer
		info["transport_protocol"] = connection.UDP
		i.handleLocalUDP(s, &localDatagrams{PacketTransport: conn, peer: peer, info: info})
	}
}

func localExtra(tunnel *local.TunnelInfo) map[string]any {
	info := make(map[string]any)
	if tunnel != nil {
		if tunnel.Pid != nil {
			info["pid"] = *tunnel.Pid
		}
		if tunnel.ProcessName != nil {
			info["process_name"] = *tunnel.ProcessName
		}
	}
	return info
}

type localStream struct {
	net.Conn
	info map[string]any
}

func (c *localStream) CloseWrite() error {
	if stream, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return stream.CloseWrite()
	}
	return c.Close()
}

func (c *localStream) GetExtraInfo(key string) (any, bool) {
	value, ok := c.info[key]
	return value, ok
}

type localDatagrams struct {
	layer.PacketTransport
	peer netip.AddrPort
	info map[string]any
}

func (c *localDatagrams) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.peer) }
func (c *localDatagrams) LocalAddr() net.Addr  { return c.PacketTransport.RemoteAddr() }
func (c *localDatagrams) GetExtraInfo(key string) (any, bool) {
	value, ok := c.info[key]
	return value, ok
}

func (c *localDatagrams) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := c.PacketTransport.ReadFrom(p)
	return n, c.RemoteAddr(), err
}

func (c *localDatagrams) WriteTo(p []byte, peer net.Addr) (int, error) {
	if peer != nil && (peer.Network() != "udp" || peer.String() != c.RemoteAddr().String()) {
		return 0, errors.New("local UDP peer differs from fixed tuple")
	}
	return c.PacketTransport.WriteTo(p, nil)
}
