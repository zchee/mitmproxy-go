// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modeserver"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
)

func init() {
	modeserver.RegisterListenerFactory(modeserver.ListenerKey{Scheme: "http3", Transport: connection.UDP}, listenHTTP3Packets)
}

func listenHTTP3Packets(ctx context.Context, socket net.PacketConn, handle modeserver.PacketHandler) (io.Closer, error) {
	if socket == nil || handle == nil {
		return nil, errors.New("httplayer: HTTP/3 listener requires socket and handler")
	}
	listener := packettransport.NewListener(ctx, socket)
	go func() {
		for {
			client, err := listener.Accept(ctx)
			if err != nil {
				if errors.Is(err, layer.ErrPacketOverflow) {
					slog.ErrorContext(ctx, "Accepting proxy connection", "error", err)
					continue
				}
				return
			}
			go func() { _ = handle(client.Context(), client) }()
		}
	}()
	return listener, nil
}
