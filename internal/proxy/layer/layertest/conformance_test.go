// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layertest_test

import (
	"context"
	"io"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func TestConformance(t *testing.T) {
	layertest.Conformance(t, func(t *testing.T) layertest.Session {
		clientPeer, client := layertest.Pipe(t)
		serverPeer, server := layertest.Pipe(t)
		cr, sr := proxy.Record(client), proxy.Record(server)
		return layertest.Session{
			Client: clientPeer, Server: serverPeer,
			ClientInput: cr, ServerInput: sr,
			ClientData: []byte("request\n"), ServerData: []byte("response\n"),
			Run: func(context.Context) error {
				done := make(chan error, 2)
				relay := func(dst, src layer.Conn) {
					_, err := io.Copy(dst, src)
					if err == nil {
						err = dst.CloseWrite()
					}
					done <- err
				}
				go relay(sr, cr)
				go relay(cr, sr)
				first, second := <-done, <-done
				if first != nil {
					return first
				}
				return second
			},
		}
	})
}
