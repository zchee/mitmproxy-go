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
)

func (i *Instance) listenPacketSockets(ctx context.Context, port int) ([]net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config := new(net.ListenConfig)
	if i.host != "" {
		socket, err := config.ListenPacket(ctx, "udp", net.JoinHostPort(i.host, strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
		return []net.PacketConn{socket}, nil
	}
	ipv4, err := config.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	boundPort := ipv4.LocalAddr().(*net.UDPAddr).Port
	ipv6, err := config.ListenPacket(ctx, "udp6", net.JoinHostPort("::", strconv.Itoa(boundPort)))
	if port == 0 && isAddrInUse(err) {
		i.logger.Debug("Failed to listen on a single port, falling back to default behavior.", "error", err)
		ipv6, err = config.ListenPacket(ctx, "udp6", "[::]:0")
	}
	if err != nil {
		if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) {
			i.logger.Debug("Failed to listen on '::', listening on IPv4 only.", "error", err)
			return []net.PacketConn{ipv4}, nil
		}
		_ = ipv4.Close()
		return nil, err
	}
	return []net.PacketConn{ipv4, ipv6}, nil
}

func (i *Instance) handlePacket(ctx context.Context, client layer.PacketTransport) error {
	if admitted, limit := i.limiter.acquire(); !admitted {
		_ = client.Close()
		i.logger.Warn(fmt.Sprintf("Client connection from %s refused: max_client_connections (%d) reached.", client.RemoteAddr(), limit))
		return nil
	}
	defer i.limiter.release()
	err := i.handler.HandlePackets(ctx, client, i.mode.String(), i.top)
	if err != nil {
		i.logger.Error("Handling proxy connection", "error", err)
	}
	return err
}
