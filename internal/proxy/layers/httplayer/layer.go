// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
	wslayer "github.com/zchee/mitmproxy-go/internal/proxy/layers/websocket"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
)

func init() {
	layer.Register(hookdata.LayerHTTP, newHTTPLayer)
}

// httpLayer serialises HTTP/1 exchanges or demultiplexes HTTP/2 streams,
// the counterpart of upstream's HttpLayer driving a protocol endpoint.
// (py:mitmproxy/proxy/layers/http). Each exchange runs the stream state
// machine between the client endpoint and a lazily connected server
// endpoint; a CONNECT answered with a 2xx ends the loop and hands the
// transport, with every buffered byte, to a child layer.
type httpLayer struct {
	route    routeConfig
	child    layer.Layer
	upstream *connection.ServerSpec
}

func newHTTPLayer(c *layer.Context, spec hookdata.LayerSpec, child layer.Layer) (layer.Layer, error) {
	// Without a registered validate_inbound_headers option, as in an assembly
	// without the proxyserver addon, the smuggling check stays on: upstream's
	// default, and the safe side of a missing option.
	route := routeConfig{validateInboundHeaders: true}
	switch spec.HTTPMode {
	case hookdata.HTTPModeRegular:
		route.mode = modeRegular
	case hookdata.HTTPModeTransparent:
		route.mode = modeTransparent
	case hookdata.HTTPModeUpstream:
		route.mode = modeUpstream
	default:
		return nil, fmt.Errorf("httplayer: unsupported HTTP mode %q", spec.HTTPMode)
	}
	// The constructor runs under the dispatch lock: client metadata reads
	// are safe here. A reverse proxy serves transparent-mode requests but
	// rewrites the Host header, so the distinction comes from the mode the
	// client connected to, as upstream tests client.proxy_mode.
	var upstream *connection.ServerSpec
	if mode := c.Data.Client.ProxyMode; mode != "" {
		parsed, err := modespec.Parse(mode)
		if err != nil {
			return nil, fmt.Errorf("httplayer: %w", err)
		}
		_, route.reverse = parsed.(modespec.ReverseMode)
		if mode, ok := parsed.(modespec.UpstreamMode); ok && route.mode == modeUpstream {
			upstream = &connection.ServerSpec{Scheme: mode.Scheme, Address: connection.Address{Host: mode.Address.Host, Port: mode.Address.Port}}
		}
	}
	return &httpLayer{route: route, child: child, upstream: upstream}, nil
}

// Kind implements [layer.Layer].
func (*httpLayer) Kind() hookdata.LayerKind { return hookdata.LayerHTTP }

// Run implements [layer.Layer].
func (l *httpLayer) Run(ctx context.Context, c *layer.Context) error {
	if l.upstream != nil {
		derived := *c
		c = &derived
		pool := newUpstreamPool(ctx, c, c.Pool, false)
		defer pool.stop()
		c.Pool = pool
		if err := c.Do(ctx, func(context.Context) error {
			c.Data.Server.Via = new(*l.upstream)
			return nil
		}); err != nil {
			return err
		}
	}
	// Bytes the next-layer decision consumed replay into the request parser.
	c.Client.StopRecording()
	wire := newWireStore()
	client := newHTTP1Server(c.Client, wire, c.HTTPFidelity)
	client.logger = c.Logger
	client.clock = c.Clock
	client.handover = true

	// When a server TLS layer sits above, its derived pool already wraps
	// every opened connection in TLS; adding a setup here would nest a
	// second session inside it.
	tlsAbove := false
	if err := c.Do(ctx, func(context.Context) error {
		for _, built := range c.Data.Layers {
			if l, ok := built.(layer.Layer); ok && l.Kind() == hookdata.LayerServerTLS {
				tlsAbove = true
			}
		}
		return nil
	}); err != nil {
		return err
	}
	var setup func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)
	if !tlsAbove {
		setup = tlslayer.ServerSetup(c)
	}

	// Server endpoints persist across exchanges keyed by their transport:
	// an endpoint's parse state (buffered bytes, keep-alive position) must
	// survive into the next exchange that reuses the pooled connection.
	endpoints := newHTTPOrigins(ctx)
	defer endpoints.stop()
	settings, err := protocolSettings(ctx, c, nil)
	if err != nil {
		return err
	}
	if settings.descriptor.Protocol == "h2" {
		return l.runHTTP2(ctx, c, settings, endpoints, wire, setup)
	}
	for {
		stream := &httpStream{c: c, id: client.streamID(), route: l.exchangeRoute(c), wire: wire, clientClosed: client.done}
		// Observe an inherited or previously used origin while request hooks
		// are paused. A FIN must retire it before the pool selects a transport.
		stopIdle := func() {}
		if c.Server != nil {
			var metadata *connection.Server
			if err := c.Do(ctx, func(context.Context) error {
				metadata = c.Data.Server
				return nil
			}); err != nil {
				return err
			}
			if conn, ok := c.Pool.Lookup(metadata); ok {
				endpoint, err := endpoints.idle(ctx, c, conn, metadata, wire)
				if err != nil {
					return err
				}
				if endpoint != nil {
					idleCtx, cancel := context.WithCancel(ctx)
					done := make(chan struct{})
					go func() {
						defer close(done)
						_ = endpoint.readWait(idleCtx, true)
						if idleCtx.Err() == nil {
							endpoint.closeWrite()
						}
					}()
					stopIdle = sync.OnceFunc(func() { cancel(); <-done })
				}
			}
		}
		server := &lazyServer{ready: make(chan struct{})}
		server.acquire = func(ctx context.Context, request *httpmsg.Request) (ServerEndpoint, error) {
			return l.connect(ctx, c, stream, request, wire, endpoints, setup, server)
		}
		driver := &streamDriver{stream: stream, client: client, server: server, beforeRequest: stopIdle}
		err := driver.run(ctx)
		stopIdle()
		server.release()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if stream.priorKnowledge && !stream.failed {
			head := wire.takeRequest(stream.id)
			if head == nil || head.head == nil {
				return errors.New("httplayer: cleartext preface lost its wire head")
			}
			prefix := append(head.head.Raw, client.takeoverExact()...)
			c.Client = c.Record(prefixed(prefix, client.conn))
			settings.descriptor.Protocol = "h2"
			return l.runHTTP2(ctx, c, settings, endpoints, wire, setup)
		}
		if stream.h2c != nil && !stream.failed {
			c.Client = c.Record(prefixed(client.takeoverExact(), client.conn))
			c.Client.StopRecording()
			settings.descriptor.Protocol = "h2"
			settings.upgrade, settings.upgradeFlow = stream.h2c, stream.flow
			return l.runHTTP2(ctx, c, settings, endpoints, wire, setup)
		}
		if stream.connectEstablished {
			return l.tunnel(ctx, c, client, stream)
		}
		if stream.snapshot != nil && stream.snapshot.Response != nil && stream.snapshot.Response.StatusCode == 101 {
			var websocket, raw bool
			if err := c.Do(ctx, func(context.Context) error {
				websocket = c.Data.Options.Bool("websocket")
				raw = c.Data.Options.Bool("rawtcp")
				return nil
			}); err != nil {
				return err
			}
			if websocket && strings.EqualFold(stream.snapshot.Response.Headers.Get("Upgrade"), "websocket") {
				endpoint, ok := server.endpoint.(*http1Client)
				if !ok {
					return errors.New("httplayer: WebSocket upgrade has no HTTP/1 origin")
				}
				if err := stream.upgrade.validate(); err != nil {
					return err
				}
				handshake := stream.upgrade
				child, err := wslayer.New(wslayer.Config{
					Flow: stream.flow, Client: client.conn, Server: endpoint.conn,
					ClientBuffered: client.takeoverExact(), ServerBuffered: endpoint.takeoverExact(),
					ClientOffer:    handshake.clientRequest.Headers.GetAll("Sec-WebSocket-Extensions"),
					ClientResponse: handshake.clientResponse.Headers.GetAll("Sec-WebSocket-Extensions"),
					ServerOffer:    handshake.serverRequest.Headers.GetAll("Sec-WebSocket-Extensions"),
					ServerResponse: handshake.serverResponse.Headers.GetAll("Sec-WebSocket-Extensions"),
				})
				if err != nil {
					return err
				}
				if err := c.Do(ctx, func(context.Context) error {
					// The upgrade retains the HTTP flow until WebSocket end, so
					// injection must remain available before WebSocket start.
					stream.flow.Live = true
					c.Data.Layers = append(c.Data.Layers, child)
					return nil
				}); err != nil {
					return err
				}
				return child.Run(ctx, c)
			}
			if !raw {
				if c.Logger != nil {
					c.Logger.WarnContext(ctx, "Sent HTTP 101 response, but no protocol is enabled to upgrade to.")
				}
				// Retire both directions; the handler closes its owned transports
				// when Run returns. Announce EOF after the completed response.
				return c.Client.CloseWrite()
			}
			if endpoint, ok := server.endpoint.(*http1Client); ok {
				c.Client = c.Record(prefixed(client.takeover(), client.conn))
				c.Server = c.Record(prefixed(endpoint.takeover(), endpoint.conn))
				child, err := layer.Build(ctx, c, hookdata.LayerStack{{Kind: hookdata.LayerTCP}})
				if err != nil {
					return err
				}
				return child.Run(ctx, c)
			}
		}
		if client.done() {
			return nil
		}
	}
}

// exchangeRoute reads the per-exchange options, as upstream reads them from
// context.options at each use. Options may be absent in reduced assemblies.
func (l *httpLayer) exchangeRoute(c *layer.Context) routeConfig {
	route := l.route
	if opts := c.Data.Options; opts.Has("keep_host_header") {
		route.keepHostHeader = opts.Bool("keep_host_header")
	}
	if opts := c.Data.Options; opts.Has("validate_inbound_headers") {
		route.validateInboundHeaders = opts.Bool("validate_inbound_headers")
	}
	return route
}

// connect acquires the server connection for request, as upstream's
// make_server_connection and get_connection: the context's server metadata
// is reused when it already points at the destination, a fresh server is
// created otherwise, the SNI follows the client in transparent mode, and a
// TLS destination is set up inside the pool's establishment flight.
func (l *httpLayer) connect(ctx context.Context, c *layer.Context, stream *httpStream, request *httpmsg.Request, wire *wireStore, endpoints *httpOrigins, setup func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error), lazy *lazyServer) (ServerEndpoint, error) {
	tls := request.Scheme == "https"
	var metadata *connection.Server
	var quicOrigin bool
	if err := c.Do(ctx, func(context.Context) error {
		srv := c.Data.Server
		same := srv.Address != nil && srv.Address.Host == request.Host && srv.Address.Port == request.Port && srv.TLS == tls
		if !same {
			via := srv.Via
			srv = connection.NewServer(&connection.Address{Host: request.Host, Port: request.Port})
			srv.TransportProtocol = connection.TCP
			if tls && c.Data.Server.TransportProtocol == connection.UDP {
				srv.TransportProtocol = connection.UDP
			}
			if via != nil {
				srv.Via = new(*via)
			}
		}
		if tls {
			srv.TLS = true
			if srv.SNI == nil {
				// The address may be an IP in transparent mode: the client's
				// SNI names the host better, as upstream prefers it.
				sni := request.Host
				if same && l.route.mode == modeTransparent && c.Data.Client.SNI != nil {
					sni = *c.Data.Client.SNI
				}
				srv.SNI = &sni
			}
		}
		metadata = srv
		quicOrigin = tls && srv.TransportProtocol == connection.UDP
		if quicOrigin {
			if opts := c.Data.Options; opts != nil && opts.Has("http3") && !opts.Bool("http3") {
				return errors.New("httplayer: HTTP/3 is disabled")
			}
			// Origin protocol selection is independent of the TCP client's ALPN.
			if len(srv.ALPNOffers) == 0 {
				srv.ALPNOffers = [][]byte{[]byte("h3")}
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if quicOrigin {
		endpoint, release, actual, err := endpoints.quic.acquire(ctx, c, metadata, stream)
		if err != nil {
			return nil, err
		}
		lazy.releaseOrigin = release
		if err := c.Do(ctx, func(context.Context) error {
			c.Data.Server, stream.flow.ServerConn = actual, actual
			return nil
		}); err != nil {
			release()
			return nil, err
		}
		return endpoint, nil
	}
	if c.Pool == nil {
		return nil, errors.New("httplayer: HTTP origin requires a connection pool")
	}
	opts := layer.OpenOptions{Reuse: true}
	if tls {
		opts.Setup = setup
	}
	conn, actual, err := c.Pool.Open(ctx, metadata, opts)
	if err != nil {
		return nil, err
	}
	endpoint, release, err := endpoints.acquire(ctx, c, conn, actual, stream, request, wire)
	if errors.Is(err, errOriginInUse) {
		opts.Reuse = false
		conn, actual, err = c.Pool.Open(ctx, metadata, opts)
		if err == nil {
			endpoint, release, err = endpoints.acquire(ctx, c, conn, actual, stream, request, wire)
		}
	}
	if err != nil {
		return nil, err
	}
	lazy.releaseOrigin = release
	if err := c.Do(ctx, func(context.Context) error {
		c.Data.Server = actual
		stream.flow.ServerConn = actual
		return nil
	}); err != nil {
		return nil, err
	}
	return endpoint, nil
}

// tunnel hands an established CONNECT to a child layer: the bytes the
// endpoint consumed beyond the exchange replay ahead of the transport, a
// fresh recorder restores sniffing for the next-layer decision, and the
// connection the eager strategy opened becomes the current server.
func (l *httpLayer) tunnel(ctx context.Context, c *layer.Context, client *http1Server, stream *httpStream) error {
	if pool, ok := c.Pool.(*upstreamPool); ok {
		// A CONNECT child sends origin-form requests even without origin TLS;
		// its logical connections require tunnels rather than forwarding mode.
		tunnelPool := newUpstreamPool(ctx, c, pool.base, true)
		defer tunnelPool.stop()
		c.Pool = tunnelPool
		c.Server = nil
	}
	c.Client = c.Record(prefixed(client.takeover(), c.Client))
	if stream.connectConn != nil {
		c.Server = c.Record(stream.connectConn)
		if err := c.Do(ctx, func(context.Context) error {
			c.Data.Server = stream.connectServer
			return nil
		}); err != nil {
			return err
		}
	}
	child := l.child
	if child == nil {
		var err error
		if child, err = layer.Next(ctx, c); err != nil {
			return err
		}
	}
	return child.Run(ctx, c)
}

// lazyServer defers the server connection until the stream forwards its
// request headers, as upstream's connection strategy "lazy" and its
// make_server_connection at the first outgoing event. A failed acquisition
// becomes a ResponseProtocolError with ErrorCode ConnectFailed carrying the
// pool's error text, as upstream's GetHttpConnectionCompleted error path.
type lazyServer struct {
	acquire func(context.Context, *httpmsg.Request) (ServerEndpoint, error)

	mu            sync.Mutex
	endpoint      ServerEndpoint
	failure       *ResponseProtocolError
	done          bool
	ready         chan struct{}
	releaseOrigin func()

	// responseComplete belongs to the receiving goroutine. Once it sees the
	// end event, later bytes must stay buffered until routing takes over.
	responseComplete bool
}

func (s *lazyServer) release() {
	if s.releaseOrigin != nil {
		s.releaseOrigin()
	}
}

func (s *lazyServer) needsReadCredit() bool {
	s.mu.Lock()
	endpoint := s.endpoint
	s.mu.Unlock()
	if endpoint, ok := endpoint.(interface{ needsReadCredit() bool }); ok {
		return endpoint.needsReadCredit()
	}
	return false
}

func (s *lazyServer) waitStreamFailed(ctx context.Context) <-chan struct{} {
	select {
	case <-s.ready:
	case <-ctx.Done():
		return ctx.Done()
	}
	s.mu.Lock()
	endpoint := s.endpoint
	s.mu.Unlock()
	if endpoint, ok := endpoint.(interface {
		waitStreamFailed(context.Context) <-chan struct{}
	}); ok {
		return endpoint.waitStreamFailed(ctx)
	}
	return ctx.Done()
}

func (s *lazyServer) waitSendCredit(ctx context.Context) error {
	select {
	case <-s.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	endpoint := s.endpoint
	s.mu.Unlock()
	if endpoint, ok := endpoint.(interface{ waitSendCredit(context.Context) error }); ok {
		return endpoint.waitSendCredit(ctx)
	}
	return nil
}

func (s *lazyServer) takeReceipt() layer.ConsumptionReceipt {
	s.mu.Lock()
	endpoint := s.endpoint
	s.mu.Unlock()
	return takeEndpointReceipt(endpoint)
}

var _ ServerEndpoint = (*lazyServer)(nil)

// acquisitionError makes a failed connection attempt part of the send
// acknowledgement, before the driver accepts further request events.
type acquisitionError struct{ message string }

// Error returns the server connection acquisition failure message.
func (e *acquisitionError) Error() string { return e.message }

// Send implements [ServerEndpoint]. The first RequestHeaders acquires the
// connection; events after a failed acquisition are consumed silently, as
// upstream's errored stream consumes its remaining events.
func (s *lazyServer) Send(ctx context.Context, event RequestEvent) error {
	s.mu.Lock()
	endpoint := s.endpoint
	if endpoint == nil && !s.done {
		headers, ok := event.(RequestHeaders)
		if !ok {
			// Nothing was ever sent to a server: a client-side protocol
			// error or trailing event has no connection to report to.
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		acquired, err := s.acquire(ctx, headers.Request)
		s.mu.Lock()
		s.done = err != nil
		if err != nil {
			s.failure = &ResponseProtocolError{ID: event.StreamID(), Code: ConnectFailed, Message: err.Error()}
		} else {
			s.endpoint = acquired
		}
		endpoint = acquired
		close(s.ready)
		if err != nil {
			s.mu.Unlock()
			return &acquisitionError{message: err.Error()}
		}
	}
	failed := s.done && s.endpoint == nil
	s.mu.Unlock()
	if failed {
		return nil
	}
	return endpoint.Send(ctx, event)
}

// Receive implements [ServerEndpoint]. It parks until the connection exists
// or the exchange ends without one.
func (s *lazyServer) Receive(ctx context.Context) (ResponseEvent, error) {
	select {
	case <-s.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.mu.Lock()
	endpoint, failure := s.endpoint, s.failure
	s.failure = nil
	s.mu.Unlock()
	if failure != nil {
		return *failure, nil
	}
	if endpoint == nil {
		return nil, io.EOF
	}
	if endpoint, ok := endpoint.(*http1Client); ok && s.responseComplete {
		return endpoint.receive(ctx, true)
	}
	event, err := endpoint.Receive(ctx)
	if _, end := event.(ResponseEndOfMessage); end {
		s.responseComplete = true
	}
	return event, err
}

// prefixed returns conn preceded by the given bytes, so a handover preserves
// what the previous reader had already consumed from the transport.
func prefixed(prefix []byte, conn layer.Conn) layer.Conn {
	if len(prefix) == 0 {
		return conn
	}
	return &prefixConn{prefix: prefix, Conn: conn}
}

type prefixConn struct {
	layer.Conn
	mu     sync.Mutex
	prefix []byte
}

// Read consumes buffered prefix bytes before reading the underlying connection.
func (p *prefixConn) Read(b []byte) (int, error) {
	p.mu.Lock()
	if len(p.prefix) != 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		p.mu.Unlock()
		return n, nil
	}
	p.mu.Unlock()
	return p.Conn.Read(b)
}
