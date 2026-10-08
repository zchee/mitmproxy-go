// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
)

// poolCleanupTimeout bounds cleanup admission and each caller's shutdown wait.
// It does not interrupt addon callbacks or kernel transport closure.
const poolCleanupTimeout = 5 * time.Second

// maxFailedPoolEntries limits completed failures without expiring active flights.
const maxFailedPoolEntries = 256

type addressKey struct {
	host     string
	port     int
	scope    connection.IPv6Scope
	hasScope bool
}

type poolKey struct {
	address   addressKey
	tls       bool
	via       addressKey
	viaScheme string
	hasVia    bool
	proto     connection.TransportProtocol
	sni       string
	hasSNI    bool
}

func addressPoolKey(address connection.Address) addressKey {
	key := addressKey{host: address.Host, port: address.Port}
	if address.Scope != nil {
		key.scope, key.hasScope = *address.Scope, true
	}
	return key
}

func keyOf(srv *connection.Server) poolKey {
	key := poolKey{tls: srv.TLS, proto: srv.TransportProtocol}
	if srv.Address != nil {
		key.address = addressPoolKey(*srv.Address)
	}
	if srv.SNI != nil {
		key.sni, key.hasSNI = *srv.SNI, true
	}
	if srv.Via != nil {
		key.via, key.viaScheme, key.hasVia = addressPoolKey(srv.Via.Address), srv.Via.Scheme, true
	}
	return key
}

// A flight's result is immutable after done closes. The pool mutex protects
// replacement of the current flight by an Upgrade, not the result itself.
type poolFlight struct {
	done chan struct{}
	conn layer.Conn
	err  error
}

type poolEntry struct {
	key         poolKey
	srv         *connection.Server
	flight      *poolFlight
	upgraded    bool
	retired     bool
	leaseOnly   bool
	endComplete bool

	// Transport state is independent of addon-visible metadata. It lets
	// Lookup reject a closed transport without acquiring dispatch.
	state  atomic.Uint32
	end    sync.Once
	endErr error
}

type serverPool struct {
	ctx    context.Context
	cancel context.CancelFunc
	client *connection.Client
	dial   layer.Dialer
	hooks  layer.Hooks
	do     func(context.Context, func(context.Context) error) error

	mu         sync.Mutex
	entries    []*poolEntry
	version    uint64
	workers    sync.WaitGroup
	closed     bool
	closedDone chan struct{}
	closeErr   error
}

func newServerPool(ctx context.Context, client *connection.Client, dial layer.Dialer, hooks layer.Hooks, do func(context.Context, func(context.Context) error) error) *serverPool {
	if ctx == nil || client == nil || dial == nil || hooks == nil || do == nil {
		panic("proxy: newServerPool with a missing dependency")
	}
	ctx, cancel := context.WithCancel(ctx)
	return &serverPool{ctx: ctx, cancel: cancel, client: client, dial: dial, hooks: hooks, do: do, closedDone: make(chan struct{})}
}

// Open establishes or reuses a server connection, sharing concurrent setup attempts.
func (p *serverPool) Open(ctx context.Context, srv *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	if srv == nil {
		return nil, nil, errors.New("proxy: Open with a nil server")
	}
	var snapshot *connection.Server
	var wantsH2 bool
	if err := p.do(ctx, func(context.Context) error {
		if srv.Address == nil || srv.Address.Host == "" {
			return errors.New("proxy: cannot open connection, no hostname given")
		}
		snapshot = srv.Clone()
		wantsH2 = string(p.client.ALPN) == "h2"
		return nil
	}); err != nil {
		return nil, nil, err
	}
	key := keyOf(snapshot)
	entry, winner, err := p.claim(ctx, key, srv, snapshot, opts)
	if err != nil {
		return nil, nil, err
	}
	conn, err := p.await(ctx, entry)
	if err != nil {
		return nil, nil, err
	}
	if !winner && wantsH2 {
		var h2 bool
		if err := p.do(ctx, func(context.Context) error {
			h2 = string(entry.srv.ALPN) == "h2"
			return nil
		}); err != nil {
			return nil, nil, err
		}
		if !h2 {
			fresh := freshServer(snapshot)
			opts.Reuse = false
			entry, _, err = p.claim(ctx, key, fresh, fresh, opts)
			if err != nil {
				return nil, nil, err
			}
			conn, err = p.await(ctx, entry)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return conn, entry.srv, nil
}

// claim never acquires dispatch while holding mu, nor mu from a dispatch
// callback. Recheck the version after sampling metadata so concurrent callers
// replacing closed connections still share one new establishment.
func (p *serverPool) claim(ctx context.Context, key poolKey, srv, snapshot *connection.Server, opts layer.OpenOptions) (*poolEntry, bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, false, net.ErrClosed
		}
		version := p.version
		var candidates []*poolEntry
		duplicate := snapshot.TimestampStart != nil || snapshot.TimestampEnd != nil
		for _, entry := range p.entries {
			duplicate = duplicate || entry.srv == srv
			if !opts.Reuse || entry.retired || entry.key != key {
				continue
			}
			select {
			case <-entry.flight.done:
				if entry.flight.err != nil {
					p.mu.Unlock()
					return entry, false, nil
				}
				candidates = append(candidates, entry)
			default:
				p.mu.Unlock()
				return entry, false, nil
			}
		}
		p.mu.Unlock()
		var live *poolEntry
		if len(candidates) != 0 {
			if err := p.do(ctx, func(context.Context) error {
				for _, entry := range candidates {
					if entry.srv.State != connection.Open || entry.state.Load() != uint32(connection.Open) {
						continue
					}
					if live == nil {
						live = entry
					}
					if string(p.client.ALPN) != "h2" || string(entry.srv.ALPN) == "h2" {
						live = entry
						break
					}
				}
				return nil
			}); err != nil {
				return nil, false, err
			}
		}
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, false, net.ErrClosed
		}
		if p.version != version {
			p.mu.Unlock()
			continue
		}
		if live != nil {
			p.mu.Unlock()
			return live, false, nil
		}
		for _, entry := range candidates {
			entry.retired = true
		}
		if duplicate {
			srv = freshServer(snapshot)
		}
		flight := &poolFlight{done: make(chan struct{})}
		entry := &poolEntry{key: key, srv: srv, flight: flight, upgraded: opts.Setup != nil}
		p.entries = append(p.entries, entry)
		p.version++
		p.workers.Go(func() {
			defer func() {
				close(flight.done)
				p.mu.Lock()
				p.removeCompleted(entry)
				p.trimFailures()
				p.mu.Unlock()
			}()
			flight.conn, flight.err = p.establish(entry, opts.Setup)
		})
		p.mu.Unlock()
		return entry, true, nil
	}
}

// await rechecks the current flight after every wait so an Open cannot return
// the raw transport while an Upgrade is replacing it.
func (p *serverPool) await(ctx context.Context, entry *poolEntry) (layer.Conn, error) {
	for {
		p.mu.Lock()
		flight := entry.flight
		p.mu.Unlock()
		select {
		case <-flight.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		current, closed := entry.flight == flight, p.closed
		p.mu.Unlock()
		if !current {
			continue
		}
		if flight.err != nil {
			return nil, flight.err
		}
		if closed || entry.state.Load() == uint32(connection.Closed) {
			return nil, net.ErrClosed
		}
		return flight.conn, nil
	}
}

func freshServer(srv *connection.Server) *connection.Server {
	fresh := srv.Clone()
	fresh.ID = stateutil.NewID()
	fresh.State = connection.Closed
	fresh.Error, fresh.Peername, fresh.Sockname = nil, nil, nil
	fresh.ALPN, fresh.CertificateList, fresh.Cipher = nil, nil, nil
	fresh.TLSVersion = ""
	fresh.TimestampStart, fresh.TimestampEnd = nil, nil
	fresh.TimestampTCPSetup, fresh.TimestampTLSSetup = nil, nil
	return fresh
}

func (p *serverPool) establish(entry *poolEntry, setup func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) (layer.Conn, error) {
	srv := entry.srv
	data := &hookdata.ServerConnection{Server: srv, Client: p.client}
	if _, err := p.hooks.Fire(p.ctx, addon.ServerConnectHook{Data: data}); err != nil {
		return nil, p.connectFailed(entry, err)
	}
	var snapshot *connection.Server
	if err := p.do(p.ctx, func(context.Context) error {
		if srv.Error != nil {
			return fmt.Errorf("proxy: connection killed: %s", *srv.Error)
		}
		if srv.Address == nil || srv.Address.Host == "" {
			return errors.New("proxy: cannot open connection, no hostname given")
		}
		now := nowSeconds()
		srv.TimestampStart = &now
		snapshot = srv.Clone()
		return nil
	}); err != nil {
		return nil, p.connectFailed(entry, err)
	}
	raw, err := p.dial(p.ctx, snapshot)
	if err != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		if err == nil {
			err = errors.New("proxy: dialer returned a nil connection")
		}
		return nil, p.connectFailed(entry, err)
	}
	// Closing the socket on handler cancellation interrupts setup even when
	// a TLS wrapper is blocked on I/O instead of selecting on the context.
	interrupted := make(chan struct{})
	stopClose := context.AfterFunc(p.ctx, func() {
		_ = raw.Close()
		close(interrupted)
	})
	stop := sync.OnceFunc(func() {
		if !stopClose() {
			<-interrupted
		}
	})
	peer, local := addressOf(raw.RemoteAddr()), addressOf(raw.LocalAddr())
	_, err = p.hooks.FireFunc(p.ctx, func(context.Context) error {
		now := nowSeconds()
		srv.TimestampTCPSetup = &now
		srv.State = connection.Open
		srv.Peername, srv.Sockname = peer, local
		return nil
	}, addon.ServerConnectedHook{Data: data})
	entry.state.Store(uint32(connection.Open))
	if err != nil {
		stop()
		_ = raw.Close()
		return nil, p.end(entry, err)
	}
	conn := raw
	if setup != nil {
		conn, err = setup(p.ctx, raw, srv)
	}
	if err == nil {
		err = p.ctx.Err()
	}
	if err == nil && conn == nil {
		err = errors.New("proxy: setup returned a nil connection")
	}
	if err == nil {
		err = p.refreshKey(entry)
	}
	if err != nil {
		stop()
		_ = raw.Close()
		if conn != nil {
			_ = conn.Close()
		}
		return nil, p.end(entry, err)
	}
	return &poolConn{Conn: conn, pool: p, entry: entry, stop: stop}, nil
}

func (p *serverPool) refreshKey(entry *poolEntry) error {
	var key poolKey
	if err := p.do(p.ctx, func(context.Context) error {
		key = keyOf(entry.srv)
		return nil
	}); err != nil {
		return err
	}
	p.mu.Lock()
	if key != entry.key {
		entry.key = key
		p.version++
	}
	p.mu.Unlock()
	return nil
}

func (p *serverPool) connectFailed(entry *poolEntry, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(p.ctx), poolCleanupTimeout)
	defer cancel()
	_, err := p.hooks.FireFunc(ctx, func(context.Context) error {
		if entry.srv.Error == nil {
			reason := cause.Error()
			entry.srv.Error = &reason
		}
		entry.srv.State = connection.Closed
		return nil
	}, addon.ServerConnectErrorHook{Data: &hookdata.ServerConnection{Server: entry.srv, Client: p.client}})
	return errors.Join(cause, err, ctx.Err())
}

// Upgrade applies setup once to a pooled connection and returns its wrapped transport.
func (p *serverPool) Upgrade(ctx context.Context, srv *connection.Server, setup func(context.Context, layer.Conn, *connection.Server) (layer.Conn, error)) (layer.Conn, *connection.Server, error) {
	if srv == nil || setup == nil {
		return nil, nil, errors.New("proxy: Upgrade requires a pooled server and a setup")
	}
	p.mu.Lock()
	entry := p.find(srv)
	p.mu.Unlock()
	if entry == nil {
		return nil, nil, errors.New("proxy: server is not pooled")
	}
	conn, err := p.await(ctx, entry)
	if err != nil {
		return nil, nil, err
	}
	if err := p.refreshKey(entry); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	if !entry.upgraded {
		flight := &poolFlight{done: make(chan struct{})}
		entry.flight, entry.upgraded = flight, true
		p.version++
		p.workers.Go(func() {
			defer func() {
				close(flight.done)
				p.mu.Lock()
				p.removeCompleted(entry)
				p.trimFailures()
				p.mu.Unlock()
			}()
			wrapped, err := setup(p.ctx, conn, entry.srv)
			if err == nil {
				err = p.ctx.Err()
			}
			if err == nil && wrapped == nil {
				err = errors.New("proxy: setup returned a nil connection")
			}
			if err == nil {
				err = p.refreshKey(entry)
			}
			if err != nil {
				// Record the failure before closing the tracked connection,
				// whose Close emits the disconnection hook.
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(p.ctx), poolCleanupTimeout)
				metadataErr := p.do(cleanupCtx, func(context.Context) error {
					reason := err.Error()
					entry.srv.Error = &reason
					return nil
				})
				metadataErr = errors.Join(metadataErr, cleanupCtx.Err())
				cancel()
				closeErr := conn.Close()
				if wrapped != nil {
					_ = wrapped.Close()
				}
				flight.err = errors.Join(err, metadataErr, closeErr)
				return
			}
			flight.conn = &poolConn{Conn: wrapped, pool: p, entry: entry}
		})
	}
	p.mu.Unlock()
	conn, err = p.await(ctx, entry)
	if err != nil {
		return nil, nil, err
	}
	return conn, entry.srv, nil
}

// Lookup returns a successfully established, live pooled connection without waiting.
func (p *serverPool) Lookup(srv *connection.Server) (layer.Conn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.find(srv)
	if p.closed || entry == nil || entry.leaseOnly || entry.state.Load() == uint32(connection.Closed) {
		return nil, false
	}
	select {
	case <-entry.flight.done:
		return entry.flight.conn, entry.flight.err == nil && entry.flight.conn != nil
	default:
		return nil, false
	}
}

// Retire removes a server from new acquisitions while preserving active leases.
func (p *serverPool) Retire(srv *connection.Server) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry := p.find(srv); entry != nil && !entry.leaseOnly {
		entry.retired, entry.leaseOnly = true, true
		p.version++
	}
}

func (p *serverPool) find(srv *connection.Server) *poolEntry {
	for _, entry := range p.entries {
		if entry.srv == srv {
			return entry
		}
	}
	return nil
}

// closeAll retains one cleanup owner even when a caller stops waiting.
// closedDone signals actual completion, never a cancelled or expired wait.
func (p *serverPool) closeAll(ctx context.Context) error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		entries := slices.Clone(p.entries)
		go func() {
			p.cancel()
			// All flight creation is serialized with closed under mu. A
			// foreign callback or Close may outlive the caller's budget,
			// so ownership remains here until every worker and lease ends.
			p.workers.Wait()
			var errs []error
			for _, entry := range entries {
				if conn := entry.flight.conn; conn != nil {
					if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						errs = append(errs, err)
					}
				}
			}
			p.closeErr = errors.Join(errs...)
			close(p.closedDone)
		}()
	}
	p.mu.Unlock()
	waitCtx, cancel := context.WithTimeout(ctx, poolCleanupTimeout)
	defer cancel()
	if err := waitCtx.Err(); err != nil {
		return err
	}
	select {
	case <-p.closedDone:
		return p.closeErr
	case <-waitCtx.Done():
		return waitCtx.Err()
	}
}

// end fires once even when both directions fail while teardown is closing.
// The transport caller runs outside dispatch and holds no pool mutex.
func (p *serverPool) end(entry *poolEntry, cause error) error {
	entry.state.Store(uint32(connection.Closed))
	entry.end.Do(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(p.ctx), poolCleanupTimeout)
		defer cancel()
		_, entry.endErr = p.hooks.FireFunc(ctx, func(context.Context) error {
			now := nowSeconds()
			entry.srv.TimestampEnd = &now
			entry.srv.State = connection.Closed
			if cause != nil {
				reason := cause.Error()
				entry.srv.Error = &reason
			}
			return nil
		}, addon.ServerDisconnectedHook{Data: &hookdata.ServerConnection{Server: entry.srv, Client: p.client}})
		entry.endErr = errors.Join(entry.endErr, ctx.Err())
		p.mu.Lock()
		entry.endComplete = true
		p.removeCompleted(entry)
		p.mu.Unlock()
	})
	return errors.Join(cause, entry.endErr)
}

// removeCompleted requires mu. Failed flights remain cached; a live transport,
// including an accepted draining lease, keeps its bookkeeping until Close.
func (p *serverPool) removeCompleted(entry *poolEntry) {
	if !entry.endComplete || entry.state.Load() != uint32(connection.Closed) {
		return
	}
	select {
	case <-entry.flight.done:
	default:
		return
	}
	if entry.flight.err != nil || entry.flight.conn == nil {
		return
	}
	if index := slices.Index(p.entries, entry); index >= 0 {
		p.entries = slices.Delete(p.entries, index, index+1)
		p.version++
	}
}

// trimFailures requires mu. Entries retain insertion order; evict only completed
// failures, leaving immutable flight results available to existing waiters.
func (p *serverPool) trimFailures() {
	failed := 0
	for _, entry := range p.entries {
		select {
		case <-entry.flight.done:
			if entry.flight.err != nil {
				failed++
			}
		default:
		}
	}
	excess := failed - maxFailedPoolEntries
	if excess <= 0 {
		return
	}
	p.entries = slices.DeleteFunc(p.entries, func(entry *poolEntry) bool {
		if excess <= 0 {
			return false
		}
		select {
		case <-entry.flight.done:
			if entry.flight.err != nil {
				excess--
				return true
			}
		default:
		}
		return false
	})
	p.version++
}

func nowSeconds() float64 {
	return float64(time.Now().UnixNano()) / float64(time.Second)
}

func addressOf(addr net.Addr) *connection.Address {
	if addr == nil {
		return nil
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return &connection.Address{Host: addr.String()}
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return &connection.Address{Host: host}
	}
	return &connection.Address{Host: host, Port: number}
}
