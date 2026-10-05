// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// StartHTTPOrigin starts a plaintext HTTP/1 origin on an ephemeral loopback
// listener. The handler uses net/http semantics; use StartOrigin instead when
// raw header order, casing or wire bytes matter. When the test ends, request
// contexts are canceled, connections are closed and active handlers are joined.
// Handlers must return when their request context is canceled.
func StartHTTPOrigin(t testing.TB, handler http.Handler) *Origin {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	server := httptest.NewUnstartedServer(handler)
	server.Config.BaseContext = func(net.Listener) context.Context { return ctx }
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Start()
	t.Cleanup(func() {
		cancel()
		server.Close()
	})
	return &Origin{Addr: server.Listener.Addr().String()}
}
