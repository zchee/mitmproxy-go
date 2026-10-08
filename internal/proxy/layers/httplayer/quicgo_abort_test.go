// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h3"
)

func TestHTTP3ConsumerClientAborts(t *testing.T) {
	// py:test/mitmproxy/proxy/layers/http/test_http3.py:test_http3_client_aborts.
	// The executable upstream rows require one error hook for incomplete
	// request or response transmission, notwithstanding the older docstring.
	tests := map[string]struct {
		response bool
		streamed bool
		reset    bool
		close    bool
	}{
		"request buffered reset":             {reset: true},
		"request streamed reset":             {streamed: true, reset: true},
		"request buffered close":             {close: true},
		"request streamed close":             {streamed: true, close: true},
		"request buffered reset then close":  {reset: true, close: true},
		"request streamed reset then close":  {streamed: true, reset: true, close: true},
		"response buffered reset":            {response: true, reset: true},
		"response streamed reset":            {response: true, streamed: true, reset: true},
		"response buffered close":            {response: true, close: true},
		"response streamed close":            {response: true, streamed: true, close: true},
		"response buffered reset then close": {response: true, reset: true, close: true},
		"response streamed reset then close": {response: true, streamed: true, reset: true, close: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			started, errored, terminal := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{})
			var observed *flow.HTTPFlow
			var errorCount int
			var terminalOnce sync.Once
			addon := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				switch name {
				case "requestheaders":
					observed = f
					if !test.response {
						f.Request.Stream = test.streamed
						started <- struct{}{}
					}
				case "responseheaders":
					f.Response.Stream = test.streamed
					if test.response {
						started <- struct{}{}
					}
				case "error":
					errorCount++
					select {
					case errored <- struct{}{}:
					default:
					}
				}
			}}
			fixture, master := newTestStream(t, addon)
			if err := master.Do(ctx, func(context.Context) error {
				fixture.c.Data.Server.Address = &connection.Address{Host: "example.com", Port: 443}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			fixture.c.Do = func(ctx context.Context, fn func(context.Context) error) error {
				return master.Do(ctx, func(ctx context.Context) error {
					err := fn(ctx)
					if observed != nil && !observed.Live {
						terminalOnce.Do(func() { close(terminal) })
					}
					return err
				})
			}
			peer, client := newHTTP3ConsumerPeer(t, ctx, false)
			origin, server := newHTTP3ConsumerPeer(t, ctx, true)
			runCtx, cancel := context.WithCancel(ctx)
			joined := make(chan struct{})
			consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
			go func() { defer close(joined); _ = consumer.RunQUIC(runCtx, fixture.c, client, server) }()
			defer func() { cancel(); <-joined }()
			request, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, request, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/aborted"}})
			if test.response {
				if err := request.Close(); err != nil {
					t.Fatal(err)
				}
				upstream, err := origin.conn.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				readHTTP3TestMessage(t, upstream)
				writeHTTP3TestHeaders(t, upstream, []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: "6"}})
				writeHTTP3TestFrame(t, upstream, 0, []byte("123"))
			}
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if test.reset {
				request.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
				request.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCancelled))
			}
			if test.close && !test.reset {
				if err := peer.conn.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeRequestCancelled), "peer closed connection"); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-errored:
			case <-ctx.Done():
				t.Fatal("client abort did not produce error hook:", ctx.Err())
			}
			select {
			case <-terminal:
			case <-ctx.Done():
				t.Fatal("client abort left flow live:", ctx.Err())
			}
			if test.close && test.reset {
				if err := peer.conn.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeNoError), "peer closed connection"); err != nil {
					t.Fatal(err)
				}
			}
			if err := master.Do(ctx, func(context.Context) error {
				if errorCount != 1 || observed.Error == nil {
					return errors.New("client abort error hook count or flow error is incorrect")
				}
				if !strings.Contains(observed.Error.Msg, "stream closed by client") && !strings.Contains(observed.Error.Msg, "peer closed connection") {
					return fmt.Errorf("client abort diagnostic differs from upstream: %q", observed.Error.Msg)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
