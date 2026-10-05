// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"io"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestHTTP1BodyCompletionAfterRefusal(t *testing.T) {
	conn, peer := layertest.Pipe(t)
	endpoint := newHTTP1Server(conn, newWireStore(), nil)
	write(t, peer, "CONNECT proxy.test:80 HTTP/1.1\r\n\r\n")
	if _, err := endpoint.Receive(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Send(t.Context(), ResponseProtocolError{ID: 1, Code: RequestValidationFailed, Message: "CONNECT is not allowed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(peer); err != nil {
		t.Fatal(err)
	}
	// The reader can already be completing a body while the sender retires
	// the connection. Completion must not make the endpoint reusable again.
	if err := endpoint.readBody(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !endpoint.done() {
		t.Fatal("body completion revived a refused connection")
	}
}
