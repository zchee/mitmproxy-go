// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestLazyServerPreservesPostResponseBytes(t *testing.T) {
	tests := map[string]struct {
		response string
		trailing string
	}{
		"success: upgraded bytes": {
			response: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: custom\r\n\r\n",
			trailing: "server greeting",
		},
		"success: partial following head": {
			response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			trailing: "HTTP/1.1 20",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := layertest.Pipe(t)
			endpoint := newHTTP1Client(conn, newWireStore(), nil)
			ready := make(chan struct{})
			close(ready)
			server := &lazyServer{endpoint: endpoint, ready: ready}
			request := &httpmsg.Request{Method: "GET", Path: "/", HTTPVersion: "HTTP/1.1"}
			for _, event := range []RequestEvent{RequestHeaders{ID: 1, Request: request}, RequestEndOfMessage{ID: 1}} {
				if err := server.Send(t.Context(), event); err != nil {
					t.Fatal(err)
				}
			}
			write(t, peer, tt.response+tt.trailing)
			if err := peer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if _, err := server.Receive(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if event, err := server.Receive(t.Context()); !errors.Is(err, io.EOF) {
				t.Fatalf("Receive after response = (%#v, %v), want transport EOF without consuming another event", event, err)
			}
			if diff := gocmp.Diff(tt.trailing, string(endpoint.waitBuf)); diff != "" {
				t.Fatalf("buffered bytes after response (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLayerEarlyResponseKeepsUploadUntilOriginCloses(t *testing.T) {
	s := newLayerSession(t, nil, "connection_strategy=lazy", "stream_large_bodies=1")
	s.start(hookdata.HTTPModeRegular)
	write(t, s.client, "POST http://origin.test/ HTTP/1.1\r\nContent-Length: 8\r\n\r\n")
	origin := await(t, s.pool.origins)
	expectRead(t, origin, "POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\n")
	response := "HTTP/1.1 413 Too Large\r\nContent-Length: 0\r\n\r\n"
	write(t, origin, response)
	expectRead(t, s.client, response)
	write(t, s.client, "half")
	expectRead(t, origin, "half")
	if err := origin.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if data, err := io.ReadAll(s.client); err != nil || len(data) != 0 {
		t.Fatalf("client after origin closure = (%q, %v), want EOF without another response", data, err)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	want := []string{"requestheaders", "responseheaders", "response"}
	if diff := gocmp.Diff(want, s.a.calls); diff != "" {
		t.Fatalf("early-response hooks (-want +got):\n%s", diff)
	}
}

func TestLayerUpgrade(t *testing.T) {
	s := newLayerSession(t, nil, "connection_strategy=lazy")
	s.start(hookdata.HTTPModeRegular)
	write(t, s.client, "GET http://origin.test/ HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: custom\r\n\r\nclient greeting")
	origin := await(t, s.pool.origins)
	expectRead(t, origin, "GET / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: custom\r\n\r\n")
	response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: custom\r\n\r\n"
	write(t, origin, response+"server greeting")
	expectRead(t, s.client, response+"server greeting")
	expectRead(t, origin, "client greeting")
	write(t, s.client, "later client bytes")
	expectRead(t, origin, "later client bytes")
	write(t, origin, "later server bytes")
	expectRead(t, s.client, "later server bytes")
	if err := s.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := origin.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
}
