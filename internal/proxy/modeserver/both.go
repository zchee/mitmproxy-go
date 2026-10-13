// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"net"
)

const sharedPortAttempts = 64

type portCandidateCursor interface {
	Next(context.Context) (int, error)
}

func (i *Instance) listenBothSockets(ctx context.Context) ([]net.Listener, []net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var candidates portCandidateCursor
	if i.port == 0 && i.portCandidates != nil && (i.host == "" || net.ParseIP(i.host).To4() != nil) {
		var err error
		candidates, err = i.portCandidates(ctx)
		if err != nil {
			return nil, nil, err
		}
	}
	tcpBinds, udpBinds := 0, 0
	// Count actual family-specific calls without mutating the instance or its
	// requested port. The socket-only receiver retains native fallback policy.
	binder := &Instance{
		host: i.host, port: i.port, logger: i.logger,
		listenTCP: func(ctx context.Context, network, address string) (net.Listener, error) {
			tcpBinds++
			return i.listenTCP(ctx, network, address)
		},
		listenUDP: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			udpBinds++
			return i.listenUDP(ctx, network, address)
		},
	}
	var lastErr error
	acquisitions := 0
	for range sharedPortAttempts {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		candidate := i.port
		if candidates != nil {
			var err error
			candidate, err = candidates.Next(ctx)
			if err != nil {
				return nil, nil, fmt.Errorf("modeserver: shared acquisition stopped: candidates=%d TCP_binds=%d UDP_binds=%d: %w", acquisitions, tcpBinds, udpBinds, errors.Join(lastErr, err))
			}
		}
		acquisitions++
		streams, err := binder.listenPort(ctx, candidate)
		if err != nil {
			return nil, nil, err
		}
		port := streams[0].Addr().(*net.TCPAddr).Port
		shared := true
		for _, stream := range streams {
			shared = shared && stream.Addr().(*net.TCPAddr).Port == port
		}
		var packets []net.PacketConn
		if shared {
			packets, err = binder.listenPacketSockets(ctx, port)
		} else {
			err = errors.New("modeserver: TCP listeners selected different ports")
		}
		if err == nil {
			if err = ctx.Err(); err == nil {
				return streams, packets, nil
			}
			for _, packet := range packets {
				_ = packet.Close()
			}
		}
		for _, stream := range streams {
			_ = stream.Close()
		}
		if i.port != 0 || shared && !isSharedUDPBindRetryable(err) {
			return nil, nil, err
		}
		lastErr = err
	}
	return nil, nil, fmt.Errorf("modeserver: shared acquisition exhausted: candidates=%d TCP_binds=%d UDP_binds=%d: %w", acquisitions, tcpBinds, udpBinds, lastErr)
}
