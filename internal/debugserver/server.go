// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package debugserver

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/internal/telemetry"
)

type serverGeneration struct {
	server   *http.Server
	address  string
	served   chan struct{}
	joined   chan struct{}
	clients  sync.WaitGroup
	serveErr error
}

func (c *Controller) newServer(ctx context.Context, value string) (*serverGeneration, error) {
	address, err := parseAddress(value)
	if err != nil || address == "" {
		return nil, err
	}
	listener, err := new(net.ListenConfig).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("debugserver: bind loopback listener: %w", err)
	}
	g := &serverGeneration{address: listener.Addr().String(), served: make(chan struct{}), joined: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug", func(w http.ResponseWriter, _ *http.Request) {
		var counters telemetry.Status
		if c.cfg.Counters != nil {
			counters = c.cfg.Counters()
		}
		data, err := json.Marshal(readSnapshot(c.Status(), counters))
		if err != nil {
			http.Error(w, "runtime diagnostics unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if _, err := w.Write(data); err != nil {
			c.cfg.Logger.Debug("diagnostics response interrupted")
		}
	})
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	for _, name := range []string{"allocs", "block", "goroutine", "heap", "mutex", "threadcreate"} {
		mux.Handle("GET /debug/pprof/"+name, pprof.Handler(name))
	}
	g.server = &http.Server{
		Handler: mux, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10,
		IdleTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second,
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				g.clients.Add(1)
			case http.StateClosed, http.StateHijacked:
				g.clients.Done()
			case http.StateActive, http.StateIdle:
			}
		},
	}
	go func() {
		g.serveErr = g.server.Serve(listener)
		close(g.served)
	}()
	go func() {
		// Serve admits StateNew connections synchronously. Wait only after its
		// return, when no new connection can race with the zero-count join.
		<-g.served
		g.clients.Wait()
		close(g.joined)
	}()
	return g, nil
}

func (g *serverGeneration) stop(cleanup, grace context.Context) error {
	graceErr := g.server.Shutdown(grace)
	closeErr := g.server.Close()
	select {
	case <-g.joined:
	case <-cleanup.Done():
		select {
		case <-g.joined:
		default:
			return fmt.Errorf("debugserver: listener work did not join: %w", cleanup.Err())
		}
	}
	if !errors.Is(g.serveErr, http.ErrServerClosed) {
		return errors.Join(graceErr, closeErr, g.serveErr)
	}
	// Forced close after the graceful cutoff is successful only once all
	// connection handlers and Serve have acknowledged their completion.
	if graceErr != nil && !errors.Is(graceErr, context.Canceled) && !errors.Is(graceErr, context.DeadlineExceeded) {
		return errors.Join(graceErr, closeErr)
	}
	return closeErr
}
