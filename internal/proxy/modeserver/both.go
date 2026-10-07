// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"net"
)

const sharedPortAttempts = 64

func (i *Instance) listenBothSockets(ctx context.Context) ([]net.Listener, []net.PacketConn, error) {
	var lastErr error
	for range sharedPortAttempts {
		streams, err := i.listen(ctx)
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
			packets, err = i.listenPacketSockets(ctx, port)
		} else {
			err = errors.New("modeserver: TCP listeners selected different ports")
		}
		if err == nil {
			return streams, packets, nil
		}
		for _, stream := range streams {
			_ = stream.Close()
		}
		if i.port != 0 || shared && !isSharedUDPBindRetryable(err) {
			return nil, nil, err
		}
		lastErr = err
	}
	return nil, nil, lastErr
}
