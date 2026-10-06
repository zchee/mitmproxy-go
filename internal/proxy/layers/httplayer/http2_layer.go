// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type httpProtocolSettings struct {
	descriptor          layer.EndpointDescriptor
	validate, normalize bool
	ping                time.Duration
	upgrade             *h2.UpgradeRequest
	upgradeFlow         *flow.HTTPFlow
}

func protocolSettings(ctx context.Context, c *layer.Context, server *connection.Server) (httpProtocolSettings, error) {
	settings := httpProtocolSettings{validate: true, normalize: true, ping: 58 * time.Second}
	err := c.Do(ctx, func(context.Context) error {
		conn := &c.Data.Client.Connection
		if server != nil {
			conn = &server.Connection
		}
		settings.descriptor = layer.EndpointDescriptor{Identity: layer.EndpointID(conn.ID), ConnectionID: conn.ID, Protocol: string(conn.ALPN), FromClient: server == nil}
		if opts := c.Data.Options; opts.Has("validate_inbound_headers") {
			settings.validate = opts.Bool("validate_inbound_headers")
		}
		if opts := c.Data.Options; opts.Has("normalize_outbound_headers") {
			settings.normalize = opts.Bool("normalize_outbound_headers")
		}
		if opts := c.Data.Options; opts.Has("http2_ping_keepalive") {
			settings.ping = time.Duration(opts.Int("http2_ping_keepalive")) * time.Second
		}
		return nil
	})
	return settings, err
}

type httpOrigin struct {
	conn layer.Recorder
	h1   *http1Client
	h2   *h2.Endpoint
	busy bool
}

// Socket readers belong to protocol endpoints, not individual flow owners.
// The table is connection-scoped; each HTTP/2 exchange only leases a stream.
type httpOrigins struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	entries map[layer.Conn]*httpOrigin
	workers sync.WaitGroup
}

func newHTTPOrigins(ctx context.Context) *httpOrigins {
	ctx, cancel := context.WithCancel(ctx)
	return &httpOrigins{ctx: ctx, cancel: cancel, entries: make(map[layer.Conn]*httpOrigin)}
}

func (o *httpOrigins) stop() { o.cancel(); o.workers.Wait() }

var errOriginInUse = errors.New("HTTP origin requires a separate connection")

func (o *httpOrigins) acquire(ctx context.Context, c *layer.Context, conn layer.Conn, server *connection.Server, stream *httpStream, request *httpmsg.Request, wire *wireStore) (ServerEndpoint, func(), error) {
	settings, err := protocolSettings(ctx, c, server)
	if err != nil {
		return nil, nil, err
	}
	var inherited bool
	if err := c.Do(ctx, func(context.Context) error {
		inherited = c.Data.Server == server
		return nil
	}); err != nil {
		return nil, nil, err
	}
	o.mu.Lock()
	entry := o.entries[conn]
	if entry != nil && entry.h1 != nil && (entry.busy || request.IsHTTP2() || request.IsHTTP3()) {
		o.mu.Unlock()
		return nil, nil, errOriginInUse
	}
	if entry == nil {
		recorded := c.Server
		if recorded == nil || !inherited {
			recorded = c.Record(conn)
		}
		recorded.StopRecording()
		entry = &httpOrigin{conn: recorded}
		if settings.descriptor.Protocol == "h2" {
			entry.h2, err = h2.New(recorded, h2.Config{Descriptor: settings.descriptor, Client: true, ValidateInboundHeaders: settings.validate, PingKeepalive: settings.ping, Clock: c.Clock, Logger: c.Logger})
			if err != nil {
				o.mu.Unlock()
				return nil, nil, err
			}
			engine := entry.h2
			o.workers.Go(func() { _ = engine.Run(o.ctx); _ = recorded.Close() })
			o.workers.Go(func() {
				for {
					event, err := engine.Receive(o.ctx)
					if err != nil || event.Kind == h2.GoAway {
						if c.Pool != nil {
							c.Pool.Retire(server)
						}
					}
					if err != nil {
						return
					}
				}
			})
		} else {
			entry.h1 = newHTTP1Client(recorded, wire, c.HTTPFidelity)
			entry.h1.logger, entry.h1.clock = c.Logger, c.Clock
		}
		o.entries[conn] = entry
	}
	c.Server = entry.conn
	if entry.h1 != nil {
		entry.busy = true
		o.mu.Unlock()
		return entry.h1, func() { o.mu.Lock(); entry.busy = false; o.mu.Unlock() }, nil
	}
	engine := entry.h2
	o.mu.Unlock()
	select {
	case <-engine.Done():
		if c.Pool != nil {
			c.Pool.Retire(server)
		}
		return nil, nil, errOriginInUse
	default:
	}
	identity, err := engine.OpenStream(ctx)
	if errors.Is(err, h2.ErrDraining) {
		if c.Pool != nil {
			c.Pool.Retire(server)
		}
		return nil, nil, errOriginInUse
	}
	if err != nil {
		return nil, nil, err
	}
	endpoint := &http2Client{engine: engine, failureDone: engine.StreamFailed(identity), identity: identity, id: stream.id, normalize: settings.normalize, logger: c.Logger, clock: c.Clock}
	release := func() {
		select {
		case <-engine.StreamDone(identity):
		default:
			_ = engine.CancelStream(identity, http2.ErrCodeCancel)
		}
	}
	return endpoint, release, nil
}

func (o *httpOrigins) idle(ctx context.Context, c *layer.Context, conn layer.Conn, server *connection.Server, wire *wireStore) (*http1Client, error) {
	settings, err := protocolSettings(ctx, c, server)
	if err != nil || settings.descriptor.Protocol == "h2" {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	entry := o.entries[conn]
	if entry == nil {
		c.Server.StopRecording()
		entry = &httpOrigin{conn: c.Server, h1: newHTTP1Client(c.Server, wire, c.HTTPFidelity)}
		entry.h1.logger, entry.h1.clock = c.Logger, c.Clock
		o.entries[conn] = entry
	}
	if entry.busy {
		return nil, nil
	}
	return entry.h1, nil
}

func (l *httpLayer) runHTTP2(ctx context.Context, c *layer.Context, settings httpProtocolSettings, origins *httpOrigins, wire *wireStore, setup func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) error {
	engine, err := h2.New(c.Client, h2.Config{Descriptor: settings.descriptor, ValidateInboundHeaders: settings.validate, Clock: c.Clock, Logger: c.Logger, Upgrade: settings.upgrade})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Go(func() { _ = engine.Run(ctx); _ = c.Client.Close() })
	defer func() { cancel(); workers.Wait() }()
	for {
		head, err := engine.Receive(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if head.Kind == h2.GoAway {
			continue
		}
		if head.Err != nil {
			return head.Err
		}
		if head.Kind != h2.Headers {
			continue
		}
		derived := *c
		var data hookdata.Context
		if err := c.Do(ctx, func(context.Context) error { data = *c.Data; return nil }); err != nil {
			return err
		}
		derived.Data = &data
		exchange := &derived
		stream := &httpStream{c: exchange, id: StreamID(head.Identity.Stream), route: l.exchangeRoute(exchange), wire: wire}
		if settings.upgrade != nil && head.Identity.Stream == 1 {
			stream.flow, stream.seededUpgrade = settings.upgradeFlow, true
		}
		client := &http2Server{engine: engine, failureDone: engine.StreamFailed(head.Identity), identity: head.Identity, id: stream.id, normalize: settings.normalize, logger: c.Logger, clock: c.Clock, head: &head}
		server := &lazyServer{ready: make(chan struct{})}
		server.acquire = func(ctx context.Context, request *httpmsg.Request) (ServerEndpoint, error) {
			return l.connect(ctx, exchange, stream, request, wire, origins, setup, server)
		}
		workers.Go(func() {
			defer server.release()
			defer func() {
				select {
				case <-engine.StreamDone(head.Identity):
				default:
					_ = engine.CancelStream(head.Identity, http2.ErrCodeCancel)
				}
			}()
			_ = (&streamDriver{stream: stream, client: client, server: server}).run(ctx)
		})
	}
}
