// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h3"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type http3PausedResponseHooks struct {
	layer.Hooks
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *http3PausedResponseHooks) FireFunc(ctx context.Context, prepare func(context.Context) error, hook addon.Hook) (*layer.Snapshot, error) {
	snapshot, err := h.Hooks.FireFunc(ctx, prepare, hook)
	if _, response := hook.(addon.ResponseHeadersHook); response && err == nil {
		h.once.Do(func() { close(h.entered) })
		select {
		case <-h.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return snapshot, err
}

func TestHTTP3ConsumerTerminalJoin(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ physical bool }{
		"physical close drains terminal hook":       {physical: true},
		"external cancellation interrupts response": {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			var observed *flow.HTTPFlow
			var errorCount int
			fixture, master := newTestStream(t, &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				switch name {
				case "requestheaders":
					observed = f
				case "responseheaders":
					f.Response.Stream = true
				case "error":
					errorCount++
				}
			}})
			paused := &http3PausedResponseHooks{Hooks: fixture.c.Hooks, entered: make(chan struct{}), release: make(chan struct{})}
			fixture.c.Hooks = paused
			if err := master.Do(ctx, func(context.Context) error {
				fixture.c.Data.Server.Address = &connection.Address{Host: "example.com", Port: 443}
				return nil
			}); err != nil {
				t.Fatal(err)
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
			writeHTTP3TestHeaders(t, request, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/incomplete"}})
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
			select {
			case <-paused.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if test.physical {
				if err := peer.conn.CloseWithError(quic.ApplicationErrorCode(h3.ErrCodeRequestCancelled), "peer closed connection"); err != nil {
					t.Fatal(err)
				}
				select {
				case <-client.Context().Done():
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			// Mirror the raw owner: its consumer context ends on physical close
			// as well as on external cancellation. The gated response prevents
			// a terminal publication from finishing before this boundary.
			cancel()
			if test.physical {
				close(paused.release)
			}
			select {
			case <-joined:
			case <-ctx.Done():
				t.Fatal("consumer did not join exchanges:", ctx.Err())
			}
			if err := master.Do(ctx, func(context.Context) error {
				if errorCount != 1 || observed == nil || observed.Live || observed.Error == nil {
					return errors.New("consumer returned before exactly one terminal error publication")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !test.physical && (client.Context().Err() != nil || server.Context().Err() != nil) {
				t.Fatal("external cancellation closed borrowed connections")
			}
		})
	}
}
