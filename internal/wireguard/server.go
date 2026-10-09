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
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

// Server owns encrypted client tunnels sharing one bound socket.
// The supplied IP stack remains owned by the caller.
type Server struct {
	engines []*device.Device
	cancel  context.CancelFunc
	addr    netip.AddrPort
	done    chan struct{}
	err     error
}

// New synchronously configures and starts the ordered client peers over socket.
// Authenticated source addresses learn the last sending peer; unseen outbound
// destinations use the first configured peer.
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
	clientKeys, err := cfg.PeerKeys()
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
	router := newPacketRouter(len(clientKeys), logger)
	demux := newSocketDemux(socket, len(clientKeys), logger)
	engines := make([]*device.Device, 0, len(clientKeys))
	defer func() {
		if !started {
			cancel()
			for _, engine := range engines {
				engine.Close()
			}
		}
	}()
	for peer, text := range clientKeys {
		clientKey, err := privateKey(text)
		if err != nil {
			return nil, err
		}
		bind := &socketBind{socket: socket, cancel: cancel, logger: logger, demux: demux, peer: peer, ctx: ctx, done: make(chan struct{})}
		tunnel := &stackDevice{ctx: ctx, cancel: cancel, stack: stack, router: router, peer: peer, local: address, events: make(chan tun.Event), logger: logger}
		engine := newDevice(tunnel, bind, deviceLogger(logger))
		tunnel.engine = engine
		engines = append(engines, engine)
		configuration := fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n", hex.EncodeToString(private[:]), hex.EncodeToString(clientKey.PublicKey().Bytes()))
		if err := engine.IpcSet(configuration); err != nil {
			return nil, fmt.Errorf("configure WireGuard device: %w", err)
		}
		if err := engine.Up(); err != nil {
			return nil, fmt.Errorf("start WireGuard device: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	server := &Server{engines: engines, cancel: cancel, addr: address, done: make(chan struct{})}
	started = true
	var workers sync.WaitGroup
	workers.Go(func() { demux.run(ctx, cancel) })
	workers.Go(func() { router.run(ctx, stack, cancel) })
	for _, engine := range engines {
		workers.Go(func() {
			select {
			case <-ctx.Done():
			case <-engine.Wait():
				cancel()
			}
		})
	}
	go func() {
		<-ctx.Done()
		if err := socket.Close(); !errors.Is(err, net.ErrClosed) {
			server.err = err
		}
		for _, engine := range engines {
			engine.Close()
		}
		workers.Wait()
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
