// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/internal/tools/web/webauth"
	"github.com/zchee/mitmproxy-go/master"
)

// Config identifies the single master's existing state and authentication addon.
// Every dependency is required and must belong to that master.
type Config struct {
	Master  *master.Master
	View    *view.View
	Events  *eventstore.EventStore
	Servers *proxyserver.ProxyServer
	Auth    *webauth.WebAuth
}

// Hub owns frontend subscriptions and hijacked WebSocket connections. Construct
// with New; register Done with the master and call Close outside dispatch during
// shutdown. There is no global registry and no independent flow or event store.
type Hub struct {
	cfg         Config
	clients     map[*client]struct{}
	unsubscribe []func()
	closed      bool // Dispatch-owned, along with clients and unsubscribe.
	workers     sync.WaitGroup
	waitOnce    sync.Once
	joined      chan struct{}
}

// New registers observers under Master.Do. ctx is used only for registration;
// asynchronous work never inherits its dispatch frame. It fails on missing
// dependencies or failed dispatch acquisition, without starting any goroutines.
func New(ctx context.Context, cfg Config) (*Hub, error) {
	if cfg.Master == nil || cfg.View == nil || cfg.Events == nil || cfg.Servers == nil || cfg.Auth == nil {
		return nil, errors.New("updates: all configuration dependencies are required")
	}
	h := &Hub{cfg: cfg, clients: make(map[*client]struct{}), joined: make(chan struct{})}
	err := cfg.Master.Do(ctx, func(context.Context) error {
		h.unsubscribe = []func(){
			cfg.View.Observe(h.flowChanged), cfg.Events.Observe(h.eventChanged),
			cfg.Servers.SubscribeServerState(h.serverChanged),
			cfg.Master.Options.Subscribe(h.optionsChanged),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return h, nil
}

// Done unregisters observers and signals shutdown without network I/O or joining.
// It is idempotent and requires addon dispatch, like the observer APIs it owns.
func (h *Hub) Done(context.Context) error {
	if h.closed {
		return nil
	}
	h.closed = true
	for _, unsubscribe := range h.unsubscribe {
		unsubscribe()
	}
	h.unsubscribe = nil
	for c := range h.clients {
		c.terminate(gows.CloseGoingAway, "Going away.")
	}
	return nil
}

// Close requests Done and joins every accepted connection outside dispatch.
// If ctx expires, it aborts I/O before joining and returns the context error.
// Repeated and concurrent calls are safe; no new client is admitted after Done.
func (h *Hub) Close(ctx context.Context) error {
	var clients []*client
	if err := h.cfg.Master.Do(context.WithoutCancel(ctx), func(ctx context.Context) error {
		_ = h.Done(ctx)
		for c := range h.clients {
			clients = append(clients, c)
		}
		return nil
	}); err != nil {
		return err
	}
	h.waitOnce.Do(func() { go func() { h.workers.Wait(); close(h.joined) }() })
	select {
	case <-h.joined:
		return nil
	case <-ctx.Done():
		for _, c := range clients {
			c.abort()
		}
		<-h.joined
		return ctx.Err()
	}
}

// ServeHTTP authenticates outside dispatch and performs the HTTP upgrade with
// validated pending response headers.
// It owns its handler lifetime until the reader and writer have both joined.
// Do not wrap it in a second authentication or compression middleware.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	open := false
	if err := h.cfg.Master.Do(r.Context(), func(context.Context) error { open = !h.closed; return nil }); err != nil || !open {
		http.Error(w, "Service unavailable.", http.StatusServiceUnavailable)
		return
	}
	if !h.cfg.Auth.PrepareUpgrade(w, r) {
		return
	}
	if !sameOrigin(r) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, "<html><title>403: Forbidden</title><body>403: Forbidden</body></html>")
		return
	}
	u := gows.Upgrader{ForwardResponseHeaders: true, OriginCheck: func([]byte) bool { return sameOrigin(r) }}
	conn, hs, err := u.UpgradeHTTP(w, r)
	if err != nil {
		// gows writes a generic 500 before returning rejected response-header errors.
		// Other errors already emitted HTTP policy or closed the hijacked socket.
		return
	}
	c := newClient(h, gows.NewServerConn(conn, gows.WithBuffered(hs.Buffered), gows.WithReadLimit(messageLimit)))
	admitted := false
	err = h.cfg.Master.Do(r.Context(), func(context.Context) error {
		if !h.closed {
			h.clients[c] = struct{}{}
			h.workers.Add(1)
			admitted = true
		}
		return nil
	})
	if err != nil || !admitted {
		c.abort()
		return
	}
	defer close(c.done)
	defer h.workers.Done()
	defer func() {
		_ = h.cfg.Master.Do(context.WithoutCancel(r.Context()), func(context.Context) error { delete(h.clients, c); return nil })
	}()
	c.run(r.Context())
}

// Tornado 6.5.10 compares lowercased Origin netloc to raw Host, including ports.
// Header presence matters: empty Origin rejects and prevents the legacy fallback.
func sameOrigin(r *http.Request) bool {
	values, present := r.Header[http.CanonicalHeaderKey("Origin")]
	if !present {
		values, present = r.Header[http.CanonicalHeaderKey("Sec-WebSocket-Origin")]
	}
	if !present {
		return true
	}
	origin, err := url.Parse(strings.Join(values, ","))
	if err != nil || origin.Host == "" || origin.User != nil {
		return false
	}
	return strings.ToLower(origin.Host) == r.Host
}
