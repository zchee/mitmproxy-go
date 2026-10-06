// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

func (i *Instance) listenPackets(ctx context.Context) ([]*packettransport.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config := new(net.ListenConfig)
	if i.host != "" {
		socket, err := config.ListenPacket(ctx, "udp", net.JoinHostPort(i.host, strconv.Itoa(i.port)))
		if err != nil {
			return nil, err
		}
		return []*packettransport.Listener{packettransport.NewListener(ctx, socket)}, nil
	}
	ipv4, err := config.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(i.port)))
	if err != nil {
		return nil, err
	}
	port := ipv4.LocalAddr().(*net.UDPAddr).Port
	ipv6, err := config.ListenPacket(ctx, "udp6", net.JoinHostPort("::", strconv.Itoa(port)))
	if i.port == 0 && isAddrInUse(err) {
		i.logger.Debug("Failed to listen on a single port, falling back to default behavior.", "error", err)
		ipv6, err = config.ListenPacket(ctx, "udp6", "[::]:0")
	}
	if err != nil {
		if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) {
			i.logger.Debug("Failed to listen on '::', listening on IPv4 only.", "error", err)
			return []*packettransport.Listener{packettransport.NewListener(ctx, ipv4)}, nil
		}
		_ = ipv4.Close()
		return nil, err
	}
	return []*packettransport.Listener{packettransport.NewListener(ctx, ipv4), packettransport.NewListener(ctx, ipv6)}, nil
}

func (i *Instance) acceptPackets(ctx context.Context, listener *packettransport.Listener) {
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
		if admitted, limit := i.limiter.acquire(); !admitted {
			_ = client.Close()
			i.logger.Warn(fmt.Sprintf("Client connection from %s refused: max_client_connections (%d) reached.", client.RemoteAddr(), limit))
			continue
		}
		go func() {
			defer i.limiter.release()
			if err := i.handler.HandlePackets(ctx, client, i.mode.String(), i.top); err != nil {
				i.logger.Error("Handling proxy connection", "error", err)
			}
		}()
	}
}
