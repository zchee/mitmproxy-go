// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zchee/gows"
)

func preferredListener(address string) (net.Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err == nil {
		return listener, nil
	}
	// Operating systems encode bind errors differently; keep malformed or
	// unresolved addresses fatal, but a preferred socket is optional.
	if listenErr, ok := errors.AsType[*net.OpError](err); !ok || listenErr.Op != "listen" || listenErr.Addr == nil {
		return nil, err
	}
	host, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		return nil, splitErr
	}
	slog.Warn("Preferred listener unavailable; using an ephemeral port", "address", address, "error", err)
	return net.Listen("tcp", net.JoinHostPort(host, "0"))
}

func startOrigin(address string) (string, func() error, error) {
	listener, err := preferredListener(address)
	if err != nil {
		return "", nil, err
	}
	var active sync.Map
	var closed atomic.Bool
	upgrader := gows.Upgrader{EnableCompression: true, AllowContextTakeover: true}
	server := &http.Server{ReadHeaderTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		raw, handshake, err := upgrader.UpgradeHTTP(w, request)
		if err != nil {
			return
		}
		options := []gows.ConnOption{gows.WithBuffered(handshake.Buffered)}
		if handshake.Compressed {
			options = append(options, gows.WithCompressionParams(handshake.CompressionParams))
		}
		conn := gows.NewServerConn(raw, options...)
		active.Store(conn, struct{}{})
		defer func() { active.Delete(conn); _ = conn.Abort() }()
		if closed.Load() {
			return
		}
		for {
			op, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(op, payload); err != nil {
				return
			}
		}
	})
	done := make(chan struct{})
	var serveErr error
	go func() { serveErr = server.Serve(listener); close(done) }()
	stop := sync.OnceValue(func() error {
		closed.Store(true)
		closeErr := server.Close()
		// net/http does not close hijacked WebSocket transports itself.
		active.Range(func(key, _ any) bool { _ = key.(*gows.Conn).Abort(); return true })
		<-done
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(closeErr, serveErr)
	})
	return listener.Addr().String(), stop, nil
}
