// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
)

// upstreamPool keeps logical origins distinct from physical proxy sockets, as
// upstream's HttpUpstreamProxy/TunnelLayer does. The entry HTTP layer installs
// it before CONNECT children add their server TLS decorator, so origin TLS runs
// only after proxy TLS and the proxy's CONNECT handshake.
type upstreamPool struct {
	c       *layer.Context
	base    layer.ServerPool
	connect bool
	ctx     context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	mu      sync.Mutex
	closed  bool
	entries map[upstreamKey]*upstreamEntry
	origins map[*connection.Server]*upstreamEntry
}

type upstreamKey struct {
	address     connection.Address
	scope       connection.IPv6Scope
	hasScope    bool
	via         connection.ServerSpec
	viaScope    connection.IPv6Scope
	hasViaScope bool
	transport   connection.TransportProtocol
	sni         string
	hasSNI      bool
	tls         bool
}

type upstreamEntry struct {
	proxy *connection.Server
	srv   *connection.Server
	key   upstreamKey
	ready chan struct{}
	conn  layer.Conn
	err   error
	wire  *upstreamConn

	// The pool mutex protects publication of the logical upgrade flight.
	// Its result is immutable once upgrade is closed.
	upgraded   bool
	upgrade    chan struct{}
	upgradeErr error
}

func newUpstreamPool(ctx context.Context, c *layer.Context, base layer.ServerPool, connect bool) *upstreamPool {
	ctx, cancel := context.WithCancel(ctx)
	return &upstreamPool{
		c: c, base: base, connect: connect, ctx: ctx, cancel: cancel,
		entries: make(map[upstreamKey]*upstreamEntry), origins: make(map[*connection.Server]*upstreamEntry),
	}
}

func (p *upstreamPool) stop() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	p.mu.Unlock()
	p.workers.Wait()
}

func upstreamIdentity(srv *connection.Server) upstreamKey {
	key := upstreamKey{transport: srv.TransportProtocol, tls: srv.TLS}
	if srv.Address != nil {
		key.address = *srv.Address
		if key.address.Scope != nil {
			key.scope, key.hasScope = *key.address.Scope, true
			key.address.Scope = nil
		}
	}
	if srv.Via != nil {
		key.via = *srv.Via
		if key.via.Address.Scope != nil {
			key.viaScope, key.hasViaScope = *key.via.Address.Scope, true
			key.via.Address.Scope = nil
		}
	}
	if srv.SNI != nil {
		key.sni, key.hasSNI = *srv.SNI, true
	}
	return key
}

func (p *upstreamPool) Open(ctx context.Context, srv *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	var snapshot *connection.Server
	if err := p.c.Do(ctx, func(context.Context) error {
		if srv == nil || srv.Address == nil || srv.Address.Host == "" {
			return errors.New("proxy: cannot open connection, no hostname given")
		}
		snapshot = srv.Clone()
		return nil
	}); err != nil {
		return nil, nil, err
	}
	if snapshot.Via == nil {
		return p.base.Open(ctx, srv, opts)
	}
	key := upstreamIdentity(snapshot)
	if key.via.Scheme != "http" && key.via.Scheme != "https" {
		return nil, nil, fmt.Errorf("unsupported upstream proxy scheme %q", key.via.Scheme)
	}
	for {
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, nil, net.ErrClosed
		}
		entry := p.entries[key]
		if pending := p.origins[srv]; entry == nil && pending != nil && opts.Reuse {
			// A hook may already have changed the metadata while the setup
			// flight has not yet published its new identity in entries.
			ready := pending.ready
			if pending.upgrade != nil {
				ready = pending.upgrade
			}
			select {
			case <-ready:
			default:
				entry = pending
			}
		}
		if opts.Reuse && entry != nil {
			p.mu.Unlock()
			conn, actual, err := p.await(ctx, entry)
			if err != nil {
				return nil, nil, err
			}
			p.mu.Lock()
			established := entry.key
			p.mu.Unlock()
			var live bool
			if err := p.c.Do(ctx, func(context.Context) error {
				current := upstreamIdentity(actual)
				// Setup hooks may fill SNI while another caller waits on the
				// same logical server. Its completed identity supersedes the
				// caller's pre-handshake snapshot, not the established socket.
				live = actual.State == connection.Open && current == established && (current == key || actual == srv)
				return nil
			}); err != nil {
				return nil, nil, err
			}
			if _, ok := p.base.Lookup(entry.proxy); ok && live {
				return conn, actual, nil
			}
			p.mu.Lock()
			if p.entries[key] == entry {
				delete(p.entries, key)
			}
			p.mu.Unlock()
			continue
		}
		if p.origins[srv] != nil {
			// Retrying a closed connection must not revive metadata belonging
			// to its earlier flows, just as the core pool creates a fresh ID.
			srv = snapshot.Clone()
			srv.ID = stateutil.NewID()
			srv.State = connection.Closed
			srv.Error, srv.Peername, srv.Sockname = nil, nil, nil
			srv.ALPN, srv.CertificateList, srv.Cipher = nil, nil, nil
			srv.TLSVersion = ""
			srv.TimestampStart, srv.TimestampEnd = nil, nil
			srv.TimestampTCPSetup, srv.TimestampTLSSetup = nil, nil
		}
		proxyAddress := snapshot.Via.Address
		proxy := connection.NewServer(&proxyAddress)
		proxy.TransportProtocol = connection.TCP
		if key.via.Scheme == "https" {
			proxy.TLS = true
			proxy.SNI = new(key.via.Address.Host)
			proxy.ALPNOffers = [][]byte{[]byte("http/1.1")}
		}
		entry = &upstreamEntry{ready: make(chan struct{}), proxy: proxy, srv: srv, key: key, upgraded: opts.Setup != nil}
		p.entries[key], p.origins[srv] = entry, entry
		p.workers.Go(func() {
			defer close(entry.ready)
			p.open(entry, opts)
		})
		p.mu.Unlock()
		return p.await(ctx, entry)
	}
}

func (p *upstreamPool) open(entry *upstreamEntry, opts layer.OpenOptions) {
	// Lifecycle hooks belong to the physical proxy, as upstream opens
	// tunnel_connection. Logical TLS hooks use the origin's own metadata.
	entry.conn, _, entry.err = p.base.Open(p.ctx, entry.proxy, layer.OpenOptions{
		Reuse: false,
		Setup: func(_ context.Context, conn layer.Conn, actual *connection.Server) (layer.Conn, error) {
			var err error
			if entry.key.via.Scheme == "https" {
				conn, err = tlslayer.ServerSetup(p.c)(p.ctx, conn, actual)
				if err != nil {
					return nil, err
				}
			}
			if p.connect || entry.key.tls {
				conn, err = p.establishTunnel(p.ctx, conn, actual, entry.key.address)
				if err != nil {
					return nil, err
				}
			}
			if err := p.c.Do(p.ctx, func(context.Context) error {
				physical := actual.Clone()
				entry.srv.State = connection.Open
				entry.srv.Peername = physical.Peername
				entry.srv.Sockname = physical.Sockname
				entry.srv.TimestampStart = physical.TimestampStart
				entry.srv.TimestampTCPSetup = physical.TimestampTCPSetup
				return nil
			}); err != nil {
				return nil, err
			}
			if opts.Setup != nil {
				conn, err = opts.Setup(p.ctx, conn, entry.srv)
				if err != nil {
					return nil, err
				}
				if conn == nil {
					return nil, errors.New("proxy: setup returned a nil connection")
				}
			}
			entry.wire = &upstreamConn{conn: conn, c: p.c, srv: entry.srv}
			return entry.wire, nil
		},
	})
	if entry.err == nil {
		entry.err = p.refresh(entry)
	}
	if entry.err != nil {
		_ = p.c.Do(context.WithoutCancel(p.ctx), func(context.Context) error {
			entry.srv.State = connection.Closed
			entry.srv.Error = new(entry.err.Error())
			entry.srv.TimestampEnd = new(stateutil.Now())
			return nil
		})
	}
}

// refresh accounts for TLS hooks filling SNI during setup, so later HTTP
// requests reuse the connection established for the client's handshake.
func (p *upstreamPool) refresh(entry *upstreamEntry) error {
	var key upstreamKey
	if err := p.c.Do(p.ctx, func(context.Context) error {
		key = upstreamIdentity(entry.srv)
		return nil
	}); err != nil {
		return err
	}
	p.mu.Lock()
	// Keep the pre-setup key for callers whose snapshot preceded the hook.
	// Reuse still validates the completed identity before returning it.
	entry.key = key
	p.entries[key] = entry
	p.mu.Unlock()
	return nil
}

func (p *upstreamPool) await(ctx context.Context, entry *upstreamEntry) (layer.Conn, *connection.Server, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-entry.ready:
	}
	if entry.err != nil {
		return nil, nil, entry.err
	}
	p.mu.Lock()
	upgrade := entry.upgrade
	p.mu.Unlock()
	if upgrade != nil {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-upgrade:
		}
		if entry.upgradeErr != nil {
			return nil, nil, entry.upgradeErr
		}
	}
	return entry.conn, entry.srv, nil
}

func (p *upstreamPool) Lookup(srv *connection.Server) (layer.Conn, bool) {
	p.mu.Lock()
	entry := p.origins[srv]
	if p.closed {
		p.mu.Unlock()
		return nil, false
	}
	if entry == nil {
		p.mu.Unlock()
		return p.base.Lookup(srv)
	}
	upgrade := entry.upgrade
	p.mu.Unlock()
	select {
	case <-entry.ready:
		if entry.err != nil {
			return nil, false
		}
	default:
		return nil, false
	}
	if upgrade != nil {
		select {
		case <-upgrade:
			if entry.upgradeErr != nil {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	return p.base.Lookup(entry.proxy)
}

func (p *upstreamPool) Upgrade(ctx context.Context, srv *connection.Server, setup func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) (layer.Conn, *connection.Server, error) {
	if srv == nil || setup == nil {
		return nil, nil, errors.New("proxy: Upgrade requires a pooled server and a setup")
	}
	p.mu.Lock()
	entry := p.origins[srv]
	p.mu.Unlock()
	if entry == nil {
		return p.base.Upgrade(ctx, srv, setup)
	}
	if _, _, err := p.await(ctx, entry); err != nil {
		return nil, nil, err
	}
	if _, ok := p.base.Lookup(entry.proxy); !ok {
		return nil, nil, net.ErrClosed
	}
	var key upstreamKey
	if err := p.c.Do(ctx, func(context.Context) error {
		key = upstreamIdentity(entry.srv)
		return nil
	}); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	if !entry.upgraded {
		entry.upgraded = true
		entry.upgrade = make(chan struct{})
		entry.key = key
		p.entries[key] = entry
		p.workers.Go(func() {
			defer close(entry.upgrade)
			wrapped, err := setup(p.ctx, entry.wire.current(), entry.srv)
			if err == nil {
				err = p.ctx.Err()
			}
			if err == nil && wrapped == nil {
				err = errors.New("proxy: setup returned a nil connection")
			}
			if err == nil {
				err = p.refresh(entry)
			}
			if err != nil {
				metadataErr := p.c.Do(context.WithoutCancel(p.ctx), func(context.Context) error {
					entry.srv.Error = new(err.Error())
					entry.proxy.Error = new(err.Error())
					return nil
				})
				// The tracked physical connection owns closure and disconnection
				// hooks even when the logical origin's handshake fails.
				entry.upgradeErr = errors.Join(err, metadataErr, entry.conn.Close())
				if wrapped != nil {
					_ = wrapped.Close()
				}
				return
			}
			entry.wire.mu.Lock()
			entry.wire.conn = wrapped
			entry.wire.mu.Unlock()
		})
	}
	p.mu.Unlock()
	return p.await(ctx, entry)
}

func (p *upstreamPool) establishTunnel(ctx context.Context, conn layer.Conn, proxy *connection.Server, target connection.Address) (layer.Conn, error) {
	host, err := idna.ToASCII(target.Host)
	if err != nil {
		return nil, err
	}
	authority := net.JoinHostPort(host, strconv.Itoa(target.Port))
	f := new(flow.HTTPFlow)
	snapshot, err := p.c.Hooks.FireFunc(ctx, func(context.Context) error {
		*f = *flow.NewHTTPFlow(p.c.Data.Client, proxy, false)
		headers := httpmsg.Headers{}
		if p.c.Data.Options.Bool("http_connect_send_host_header") {
			headers.Set("Host", authority)
		}
		now := stateutil.Now()
		f.Request = &httpmsg.Request{
			Host: target.Host, Port: target.Port, Method: "CONNECT", Authority: authority,
			HTTPVersion: "HTTP/1.1", Headers: headers, RawContent: []byte{},
			TimestampStart: now, TimestampEnd: new(now),
		}
		return nil
	}, addon.HTTPConnectUpstreamHook{Flow: f})
	if err != nil {
		return nil, err
	}
	head := http1.AssembleRequestHead(snapshot.Request, nil, false, nil)
	head = append(head, snapshot.Request.RawContent...)
	wire := newHTTP1Conn(conn, nil, nil)
	if err := wire.writeCtx(ctx, head); err != nil {
		return nil, err
	}
	var response http1.ResponseHead
	_, err = wire.readCtx(ctx, func() (int, error) {
		var err error
		response, err = http1.ReadResponseHead(wire.br)
		return 0, err
	})
	var address string
	if dispatchErr := p.c.Do(ctx, func(context.Context) error {
		address = proxy.Address.String()
		return nil
	}); dispatchErr != nil {
		return nil, dispatchErr
	}
	if err != nil {
		return nil, fmt.Errorf("Error connecting to %s: %s", address, errorMessage(err))
	}
	if response.Response.StatusCode < 200 || response.Response.StatusCode >= 300 {
		return nil, fmt.Errorf("Upstream proxy %s refused HTTP CONNECT request: %d %s", address, response.Response.StatusCode, response.Response.Reason) //nolint:staticcheck // Preserve upstream's case-sensitive refusal diagnostic.
	}
	buffered, err := wire.br.Peek(wire.br.Buffered())
	if err != nil {
		return nil, err
	}
	return prefixed(bytes.Clone(buffered), conn), nil
}

// upstreamConn is the stable transport owned by the physical pool. A logical
// upgrade replaces only its inner transport, so handler closure always reaches
// the current stream without repeating physical connection lifecycle hooks.
type upstreamConn struct {
	mu   sync.Mutex
	conn layer.Conn
	c    *layer.Context
	srv  *connection.Server
}

func (c *upstreamConn) current() layer.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

func (c *upstreamConn) Write(b []byte) (int, error)        { return c.current().Write(b) }
func (c *upstreamConn) LocalAddr() net.Addr                { return c.current().LocalAddr() }
func (c *upstreamConn) RemoteAddr() net.Addr               { return c.current().RemoteAddr() }
func (c *upstreamConn) SetDeadline(t time.Time) error      { return c.current().SetDeadline(t) }
func (c *upstreamConn) SetReadDeadline(t time.Time) error  { return c.current().SetReadDeadline(t) }
func (c *upstreamConn) SetWriteDeadline(t time.Time) error { return c.current().SetWriteDeadline(t) }

func (c *upstreamConn) Read(b []byte) (int, error) {
	n, err := c.current().Read(b)
	if errors.Is(err, io.EOF) {
		_ = c.c.Do(context.Background(), func(context.Context) error {
			c.srv.State &^= connection.CanRead
			c.srv.TimestampEnd = new(stateutil.Now())
			return nil
		})
	}
	return n, err
}

func (c *upstreamConn) Close() error {
	err := c.current().Close()
	_ = c.c.Do(context.Background(), func(context.Context) error {
		c.srv.State = connection.Closed
		c.srv.TimestampEnd = new(stateutil.Now())
		return nil
	})
	return err
}

func (c *upstreamConn) CloseWrite() error {
	err := c.current().CloseWrite()
	_ = c.c.Do(context.Background(), func(context.Context) error {
		c.srv.State &^= connection.CanWrite
		return nil
	})
	return err
}
