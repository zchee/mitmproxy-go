// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"time"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
)

// Replay runs one saved request through the ordinary HTTP stream and server pool.
// It reuses f for every lifecycle hook and discards client-facing response events.
// Call outside addon dispatch with a context whose dependencies remain valid until
// return. The caller owns the pool and must close its transports afterwards.
func Replay(ctx context.Context, c *layer.Context, f *flow.HTTPFlow, mode hookdata.HTTPMode) error {
	var events []RequestEvent
	if err := c.Do(ctx, func(context.Context) error {
		if f == nil || f.Request == nil || f.Request.RawContent == nil {
			return errors.New("httplayer: replay requires a complete request")
		}
		if f.Request.IsHTTP2() || f.Request.IsHTTP3() {
			return errors.New("httplayer: replay requires HTTP/1")
		}
		request := f.Request.Clone()
		request.Authority = ""
		if mode == hookdata.HTTPModeUpstream && request.Scheme == "http" {
			request.Authority = httpmsg.HostPort(request.Scheme, request.Host, request.Port)
		}
		now := float64(time.Now().UnixNano()) / 1e9
		request.TimestampStart = now
		request.TimestampEnd = new(now)
		content := request.RawContent
		trailers := request.Trailers.Clone()
		request.RawContent = nil
		request.Trailers = nil
		events = append(events, RequestHeaders{ID: 1, Request: request, ReplayFlow: f, EndStream: len(content) == 0 && len(trailers) == 0})
		for len(content) > 0 {
			n := min(len(content), http1BodyChunk)
			events = append(events, RequestData{ID: 1, Data: content[:n]})
			content = content[n:]
		}
		if len(trailers) > 0 {
			events = append(events, RequestTrailers{ID: 1, Trailers: trailers})
		}
		events = append(events, RequestEndOfMessage{ID: 1})
		return nil
	}); err != nil {
		return err
	}
	var built layer.Layer
	err := c.Do(ctx, func(context.Context) error {
		var err error
		built, err = newHTTPLayer(c, hookdata.LayerSpec{Kind: hookdata.LayerHTTP, HTTPMode: mode}, nil)
		if err == nil {
			c.Data.Layers = append(c.Data.Layers, built)
		}
		return err
	})
	if err != nil {
		return err
	}
	l := built.(*httpLayer)
	if l.upstream != nil {
		derived := *c
		c = &derived
		pool := newUpstreamPool(ctx, c, c.Pool, false)
		defer pool.stop()
		c.Pool = pool
	}
	wire := newWireStore()
	stream := &httpStream{c: c, id: 1, route: l.exchangeRoute(c), wire: wire, clientClosed: func() bool { return false }}
	endpoints := make(map[layer.Conn]*http1Client)
	server := &lazyServer{ready: make(chan struct{})}
	server.acquire = func(ctx context.Context, r *httpmsg.Request) (ServerEndpoint, error) {
		return l.connect(ctx, c, stream, r, wire, endpoints, tlslayer.ServerSetup(c))
	}
	client := &replayClient{events: events}
	return (&streamDriver{stream: stream, client: client, server: server}).run(ctx)
}

// replayClient owns a single request snapshot; it never reads a live flow.
type replayClient struct{ events []RequestEvent }

func (c *replayClient) Receive(ctx context.Context) (RequestEvent, error) {
	if len(c.events) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	event := c.events[0]
	c.events[0] = nil
	c.events = c.events[1:]
	return event, nil
}

func (*replayClient) Send(context.Context, ResponseEvent) error { return nil }
