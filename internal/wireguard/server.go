// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

// Server owns one encrypted client tunnel and its socket and virtual packet device.
// The supplied IP stack remains owned by the caller.
type Server struct {
	engine *device.Device
	bind   *socketBind
	cancel context.CancelFunc
	addr   netip.AddrPort
	done   chan struct{}
	err    error
}

// New synchronously configures and starts a single client peer over socket.
// It consumes the bound UDP socket even on error, but never closes stack.
// While active, it exclusively consumes stack.Outbound; the caller owns accepted
// TCP and UDP transports. Cancellation stops and joins the server workers.
// A nil logger selects slog.Default. Invalid keys return "Invalid key.".
func New(ctx context.Context, socket net.PacketConn, cfg Config, stack *netstack.Stack, logger *slog.Logger) (_ *Server, err error) {
	if socket == nil {
		return nil, errors.New("WireGuard requires a UDP socket")
	}
	started := false
	defer func() {
		if !started {
			closeErr := socket.Close()
			if !errors.Is(closeErr, net.ErrClosed) {
				err = errors.Join(err, closeErr)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if stack == nil {
		return nil, errors.New("WireGuard requires an IP stack")
	}
	bound, ok := socket.LocalAddr().(*net.UDPAddr)
	if !ok || bound.Port <= 0 || bound.Port > 65535 {
		return nil, errors.New("WireGuard requires a bound UDP socket")
	}
	if err := socket.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("prepare WireGuard socket: %w", err)
	}
	if err := socket.SetWriteDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("prepare WireGuard socket: %w", err)
	}
	serverKey, err := privateKey(cfg.ServerKey)
	if err != nil {
		return nil, err
	}
	clientKey, err := privateKey(cfg.ClientKey)
	if err != nil {
		return nil, err
	}
	// The WireGuard IPC zero key means "unset". Clamp through the library's
	// parser so even an all-zero X25519 secret has its valid upstream meaning.
	var private device.NoisePrivateKey
	if err := private.FromHex(hex.EncodeToString(serverKey.Bytes())); err != nil {
		return nil, errInvalidKey
	}
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	address := bound.AddrPort()
	address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	bind := &socketBind{socket: socket, cancel: cancel, logger: logger}
	tunnel := &stackDevice{ctx: ctx, cancel: cancel, stack: stack, local: address, events: make(chan tun.Event), logger: logger}
	engine := newDevice(tunnel, bind, deviceLogger(logger))
	tunnel.engine = engine
	defer func() {
		if !started {
			cancel()
			engine.Close()
		}
	}()
	configuration := fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n", hex.EncodeToString(private[:]), hex.EncodeToString(clientKey.PublicKey().Bytes()))
	if err := engine.IpcSet(configuration); err != nil {
		return nil, fmt.Errorf("configure WireGuard device: %w", err)
	}
	if err := engine.Up(); err != nil {
		return nil, fmt.Errorf("start WireGuard device: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	server := &Server{engine: engine, bind: bind, cancel: cancel, addr: address, done: make(chan struct{})}
	started = true
	go func() {
		select {
		case <-ctx.Done():
		case <-engine.Wait():
		}
		cancel()
		engine.Close()
		bind.mu.Lock()
		server.err = bind.closeErr
		bind.mu.Unlock()
		if err := socket.Close(); !errors.Is(err, net.ErrClosed) {
			server.err = errors.Join(server.err, err)
		}
		close(server.done)
	}()
	return server, nil
}

// Addr returns an independent copy of the bound UDP address.
func (s *Server) Addr() net.Addr { return net.UDPAddrFromAddrPort(s.addr) }

// Close stops the tunnel and joins its workers without stopping the caller's stack.
// It is safe to call concurrently and repeatedly.
func (s *Server) Close() error {
	s.cancel()
	<-s.done
	return s.err
}

// Done closes only after the socket, packet device and engine workers stop.
func (s *Server) Done() <-chan struct{} { return s.done }
