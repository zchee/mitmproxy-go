// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

var _ StreamRedirector = (*macOSRedirector)(nil)

// The native extension opens one Unix connection per flow, independently of
// the configuration connection. Admission and UDP queues remain bounded.
const macOSPacketQueueCapacity = 10

type macOSTCPFlow struct {
	stream *macOSStream
	flow   *TcpFlow
}

type macOSUDPFlow struct {
	transport *macOSUDPTransport
	flow      *UdpFlow
}

type macOSStream struct {
	*net.UnixConn
	owner *macOSRedirector
	once  sync.Once
	err   error
}

func (s *macOSStream) Close() error {
	s.once.Do(func() {
		s.err = s.UnixConn.Close()
		s.owner.mu.Lock()
		delete(s.owner.streams, s)
		s.owner.mu.Unlock()
	})
	return s.err
}

func (r *macOSRedirector) AcceptTCP(ctx context.Context) (net.Conn, *TcpFlow, error) {
	if err := r.acceptError(ctx); err != nil {
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-r.closedCh:
		return nil, nil, net.ErrClosed
	case err := <-r.flowErrors:
		return nil, nil, err
	case next := <-r.tcp:
		if err := r.acceptError(ctx); err != nil {
			_ = next.stream.Close()
			return nil, nil, err
		}
		return next.stream, next.flow, nil
	}
}

func (r *macOSRedirector) AcceptUDP(ctx context.Context) (layer.PacketTransport, *UdpFlow, error) {
	if err := r.acceptError(ctx); err != nil {
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-r.closedCh:
		return nil, nil, net.ErrClosed
	case err := <-r.flowErrors:
		return nil, nil, err
	case next := <-r.udp:
		if err := r.acceptError(ctx); err != nil {
			_ = next.transport.Close()
			return nil, nil, err
		}
		return next.transport, next.flow, nil
	}
}

func (r *macOSRedirector) acceptError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	if r.control == nil {
		return errors.New("macOS redirector has not launched")
	}
	return nil
}

func (r *macOSRedirector) acceptStreams(ctx context.Context, listener *net.UnixListener) {
	for {
		select {
		case r.handshakes <- struct{}{}:
		case <-ctx.Done():
			return
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			<-r.handshakes
			r.shutdown()
			return
		}
		stream := &macOSStream{UnixConn: conn, owner: r}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			_ = stream.Close()
			<-r.handshakes
			return
		}
		r.streams[stream] = struct{}{}
		r.mu.Unlock()
		r.workers.Go(func() {
			defer func() { <-r.handshakes }()
			if err := r.admitStream(ctx, stream); err != nil {
				_ = stream.Close()
				select {
				case r.flowErrors <- err:
				case <-ctx.Done():
				}
			}
		})
	}
}

func (r *macOSRedirector) admitStream(ctx context.Context, stream *macOSStream) error {
	if err := stream.SetReadDeadline(time.Now().Add(r.connectTimeout)); err != nil {
		return err
	}
	var message NewFlow
	if err := readIPC(stream, &message); err != nil {
		return fmt.Errorf("macOS flow handshake: %w", err)
	}
	switch flow := message.Message.(type) {
	case *NewFlow_Tcp:
		if flow.Tcp == nil || flow.Tcp.RemoteAddress == nil || flow.Tcp.RemoteAddress.Host == "" || flow.Tcp.RemoteAddress.Port > 65535 {
			return errors.New("invalid macOS TCP flow address")
		}
		if err := stream.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		select {
		case r.tcp <- macOSTCPFlow{stream: stream, flow: flow.Tcp}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case *NewFlow_Udp:
		if flow.Udp == nil || flow.Udp.TunnelInfo == nil {
			return errors.New("missing macOS UDP flow metadata")
		}
		local, err := macOSUDPAddress(flow.Udp.LocalAddress)
		if err != nil {
			return err
		}
		var first UdpPacket
		if err := readIPC(stream, &first); err != nil {
			return fmt.Errorf("macOS first UDP packet: %w", err)
		}
		remote, err := macOSUDPAddress(first.RemoteAddress)
		if err != nil {
			return err
		}
		if len(first.Data) > layer.MaxUDPPacketBytes {
			return layer.ErrPacketOverflow
		}
		if err := stream.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		life, cancel := context.WithCancelCause(ctx)
		transport := &macOSUDPTransport{stream: stream, ctx: life, cancel: cancel, local: local, remote: remote, packets: make(chan []byte, macOSPacketQueueCapacity), slots: make(chan struct{}, macOSPacketQueueCapacity), done: make(chan struct{}), readWake: make(chan struct{})}
		transport.slots <- struct{}{}
		transport.packets <- first.Data
		r.workers.Go(transport.readLoop)
		select {
		case r.udp <- macOSUDPFlow{transport: transport, flow: flow.Udp}:
			return nil
		case <-ctx.Done():
			_ = transport.Close()
			return ctx.Err()
		}
	default:
		return errors.New("missing macOS flow type")
	}
}

func macOSUDPAddress(address *Address) (netip.AddrPort, error) {
	if address == nil || address.Port > 65535 {
		return netip.AddrPort{}, errors.New("invalid macOS UDP address")
	}
	ip, err := netip.ParseAddr(address.Host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("macOS UDP address: %w", err)
	}
	return netip.AddrPortFrom(ip, uint16(address.Port)), nil
}

type macOSUDPTransport struct {
	stream        *macOSStream
	ctx           context.Context
	cancel        context.CancelCauseFunc
	local, remote netip.AddrPort
	packets       chan []byte
	slots         chan struct{}
	done          chan struct{}
	once          sync.Once
	writeMu       sync.Mutex
	readMu        sync.Mutex
	readDeadline  time.Time
	readWake      chan struct{}
}

var _ layer.PacketTransport = (*macOSUDPTransport)(nil)

func (t *macOSUDPTransport) Context() context.Context { return t.ctx }
func (t *macOSUDPTransport) LocalAddr() net.Addr      { return net.UDPAddrFromAddrPort(t.local) }
func (t *macOSUDPTransport) RemoteAddr() net.Addr     { return net.UDPAddrFromAddrPort(t.remote) }

func (t *macOSUDPTransport) readLoop() {
	defer close(t.done)
	defer func() {
		for {
			select {
			case <-t.packets:
			default:
				return
			}
		}
	}()
	for {
		select {
		case t.slots <- struct{}{}:
		case <-t.ctx.Done():
			return
		}
		var packet UdpPacket
		if err := readIPC(t.stream, &packet); err != nil {
			t.fail(err)
			return
		}
		remote, err := macOSUDPAddress(packet.RemoteAddress)
		if err != nil || remote != t.remote {
			t.fail(errors.New("macOS UDP packet destination changed"))
			return
		}
		if len(packet.Data) > layer.MaxUDPPacketBytes {
			t.fail(layer.ErrPacketOverflow)
			return
		}
		select {
		case t.packets <- packet.Data:
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *macOSUDPTransport) fail(err error) {
	t.once.Do(func() {
		t.cancel(errors.Join(net.ErrClosed, err))
		_ = t.stream.Close()
	})
}

func (t *macOSUDPTransport) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if t.ctx.Err() != nil {
			return 0, nil, errors.Join(net.ErrClosed, context.Cause(t.ctx))
		}
		t.readMu.Lock()
		deadline, wake := t.readDeadline, t.readWake
		t.readMu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var packet []byte
		var received bool
		select {
		case packet = <-t.packets:
			received = true
		case <-t.ctx.Done():
		case <-wake:
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
		if received {
			<-t.slots
			return copy(p, packet), t.RemoteAddr(), nil
		}
	}
}

func (t *macOSUDPTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr != nil && (addr.Network() != "udp" || addr.String() != t.RemoteAddr().String()) {
		return 0, errors.New("macOS UDP packet peer differs from fixed tuple")
	}
	if len(p) > layer.MaxUDPPacketBytes {
		t.fail(layer.ErrPacketOverflow)
		return 0, layer.ErrPacketOverflow
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if t.ctx.Err() != nil {
		return 0, errors.Join(net.ErrClosed, context.Cause(t.ctx))
	}
	packet := &UdpPacket{Data: p, RemoteAddress: &Address{Host: t.remote.Addr().String(), Port: uint32(t.remote.Port())}}
	if err := writeIPC(t.stream, packet); err != nil {
		t.fail(err)
		return 0, err
	}
	return len(p), nil
}

func (t *macOSUDPTransport) Close() error {
	t.fail(net.ErrClosed)
	<-t.done
	return nil
}

func (t *macOSUDPTransport) SetDeadline(deadline time.Time) error {
	if err := t.SetReadDeadline(deadline); err != nil {
		return err
	}
	return t.SetWriteDeadline(deadline)
}

func (t *macOSUDPTransport) SetReadDeadline(deadline time.Time) error {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if t.ctx.Err() != nil {
		return net.ErrClosed
	}
	t.readDeadline = deadline
	close(t.readWake)
	t.readWake = make(chan struct{})
	return nil
}

func (t *macOSUDPTransport) SetWriteDeadline(deadline time.Time) error {
	return t.stream.SetWriteDeadline(deadline)
}
