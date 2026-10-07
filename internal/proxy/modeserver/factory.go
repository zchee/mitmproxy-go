// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

// ListenerKey identifies a reverse protocol's listener factory. Scheme is the
// lowercase server scheme; Transport must be UDP. TCP uses stream acceptance.
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

func (i *Instance) packetFactory() (ListenerFactory, error) {
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

func (i *Instance) servePackets(ctx context.Context, socket net.PacketConn, handle PacketHandler) (io.Closer, error) {
	listener := packettransport.NewListener(ctx, socket)
	go func() {
		for {
			client, err := listener.Accept(ctx)
			if err != nil {
				if errors.Is(err, layer.ErrPacketOverflow) {
					i.logger.Error("Accepting proxy connection", "error", err)
					continue
				}
				if !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
					i.logger.Error("Accepting proxy connection", "error", err)
				}
				return
			}
			go func() { _ = handle(client.Context(), client) }()
		}
	}()
	return listener, nil
}
