// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

// ListenerKey identifies a protocol's listener factory. Scheme is the lowercase
// server scheme ("dns" also covers standalone DNS); Transport must be UDP.
// TCP uses stream acceptance.
type ListenerKey struct {
	Scheme    string
	Transport connection.TransportProtocol
}

// PacketHandler serves one accepted fixed tuple outside addon dispatch. It may
// block until the connection ends and owns the accepted transport's lifecycle.
// A factory must not invoke it while holding its listener or registry lock.
type PacketHandler func(context.Context, layer.PacketTransport) error

// ListenerFactory adapts an already bound UDP socket outside addon dispatch.
// Success transfers socket and accepted transport ownership to the returned
// non-nil closer. Close must evict tuples and release the socket without waiting
// for handlers; ctx cancellation must do the same. Failure leaves socket cleanup
// to the caller. The factory may start accepting before it returns. Each accepted
// tuple is handed to handle once, on its own goroutine, with a cancellable context.
type ListenerFactory func(ctx context.Context, socket net.PacketConn, handle PacketHandler) (io.Closer, error)

var listenerRegistry sync.Map // ListenerKey -> ListenerFactory.

// RegisterListenerFactory supplies a protocol's default UDP listener factory.
// Protocol packages call it during init, before any instance is constructed;
// mode metadata packages must not import those protocol implementations.
// Duplicate keys, nil factories, empty schemes and non-UDP transports panic.
// New copies registered factories; later registration cannot change an existing
// instance, and explicit Config.ListenerFactories entries override defaults.
func RegisterListenerFactory(key ListenerKey, factory ListenerFactory) {
	if factory == nil || key.Scheme == "" || key.Transport != connection.UDP {
		panic(fmt.Sprintf("modeserver: invalid listener factory for %q over %q", key.Scheme, key.Transport))
	}
	if _, loaded := listenerRegistry.LoadOrStore(key, factory); loaded {
		panic(fmt.Sprintf("modeserver: listener factory for %q over %q registered twice", key.Scheme, key.Transport))
	}
}

func registeredFactories(overrides map[ListenerKey]ListenerFactory) map[ListenerKey]ListenerFactory {
	factories := make(map[ListenerKey]ListenerFactory)
	listenerRegistry.Range(func(key, value any) bool {
		factories[key.(ListenerKey)] = value.(ListenerFactory)
		return true
	})
	maps.Copy(factories, overrides)
	return factories
}

func (i *Instance) packetFactory() (ListenerFactory, error) {
	if _, ok := i.mode.(modespec.DNSMode); ok {
		if factory := i.factories[ListenerKey{Scheme: "dns", Transport: connection.UDP}]; factory != nil {
			return factory, nil
		}
	}
	reverse, ok := i.mode.(modespec.ReverseMode)
	if !ok {
		return i.servePackets, nil
	}
	key := ListenerKey{Scheme: reverse.Scheme, Transport: connection.UDP}
	if factory := i.factories[key]; factory != nil {
		return factory, nil
	}
	switch reverse.Scheme {
	case "dns", "quic", "http3":
		return nil, fmt.Errorf("modeserver: reverse scheme %q is not implemented yet", reverse.Scheme)
	default:
		return i.servePackets, nil
	}
}

func init() {
	RegisterListenerFactory(ListenerKey{Scheme: "dns", Transport: connection.UDP}, func(ctx context.Context, socket net.PacketConn, handle PacketHandler) (io.Closer, error) {
		return newPacketListener(ctx, socket, handle, slog.Default()), nil
	})
}

func (i *Instance) servePackets(ctx context.Context, socket net.PacketConn, handle PacketHandler) (io.Closer, error) {
	return newPacketListener(ctx, socket, handle, i.logger), nil
}

func newPacketListener(ctx context.Context, socket net.PacketConn, handle PacketHandler, logger *slog.Logger) *packettransport.Listener {
	listener := packettransport.NewListener(ctx, socket)
	go func() {
		for {
			client, err := listener.Accept(ctx)
			if err != nil {
				if errors.Is(err, layer.ErrPacketOverflow) {
					logger.Error("Accepting proxy connection", "error", err)
					continue
				}
				if !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
					logger.Error("Accepting proxy connection", "error", err)
				}
				return
			}
			go func() { _ = handle(client.Context(), client) }()
		}
	}()
	return listener
}

func (i *Instance) startPacketFactories(ctx context.Context, port int, factory ListenerFactory, handle PacketHandler) ([]io.Closer, []connection.Address, error) {
	sockets, err := i.listenPacketSockets(ctx, port)
	if err != nil {
		return nil, nil, err
	}
	return activatePacketFactories(ctx, sockets, factory, handle)
}

func activatePacketFactories(ctx context.Context, sockets []net.PacketConn, factory ListenerFactory, handle PacketHandler) ([]io.Closer, []connection.Address, error) {
	listeners := make([]io.Closer, 0, len(sockets))
	addrs := make([]connection.Address, 0, len(sockets))
	for n, socket := range sockets {
		addr := socket.LocalAddr().(*net.UDPAddr)
		listener, err := factory(ctx, socket, handle)
		if err == nil && listener == nil {
			err = errors.New("modeserver: listener factory returned a nil closer")
		}
		if err != nil {
			for _, pending := range sockets[n:] {
				_ = pending.Close()
			}
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return nil, nil, err
		}
		listeners = append(listeners, listener)
		addrs = append(addrs, connection.Address{Host: addr.IP.String(), Port: addr.Port})
	}
	return listeners, addrs, nil
}
