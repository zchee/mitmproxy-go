// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

// ReplayRunner drives the HTTP exchange in a replay context.
// The indirection keeps proxy independent of httplayer, whose tests import proxy.
// The runner must return after a single request and honor context cancellation.
type ReplayRunner func(context.Context, *layer.Context, *flow.HTTPFlow, hookdata.HTTPMode) error

// Replay sends f's saved HTTP/1 request through ordinary proxy hooks and writes
// the response into f. cfg.Manager and cfg.Options are required; Connections
// is not used because a replay has no live client socket. A nil mode means
// direct origin replay; an upstream mode routes through its configured proxy.
// Call outside addon dispatch. Every server transport is closed before return.
func Replay(ctx context.Context, cfg Config, f *flow.HTTPFlow, mode modespec.Mode, run ReplayRunner) (err error) {
	if cfg.Manager == nil || cfg.Options == nil || run == nil {
		return errors.New("proxy: Replay requires Manager, Options and a runner")
	}
	var client *connection.Client
	var server *connection.Server
	var id string
	httpMode := hookdata.HTTPModeTransparent
	if err := cfg.Manager.Do(ctx, func(context.Context) error {
		if f == nil || f.Request == nil || f.ClientConn == nil {
			return errors.New("proxy: replay requires a request and client metadata")
		}
		if f.Request.RawContent == nil {
			return errors.New("proxy: replay requires saved content")
		}
		if f.Request.IsHTTP2() || f.Request.IsHTTP3() {
			return errors.New("proxy: replay requires HTTP/1")
		}
		id = f.ID
		client = f.ClientConn.Clone()
		client.State = connection.Open
		client.ProxyMode = "regular"
		server = connection.NewServer(&connection.Address{Host: f.Request.Host, Port: f.Request.Port})
		if f.Request.Scheme == "https" {
			server.TLS = true
			server.SNI = new(f.Request.PrettyHost())
		}
		if upstream, ok := mode.(modespec.UpstreamMode); ok {
			client.ProxyMode = upstream.String()
			httpMode = hookdata.HTTPModeUpstream
			server.Via = &connection.ServerSpec{Scheme: upstream.Scheme, Address: connection.Address{Host: upstream.Address.Host, Port: upstream.Address.Port}}
			if f.ServerConn != nil {
				f.ServerConn.Via = new(*server.Via)
			}
		}
		f.IsReplay = new("request")
		f.Response = nil
		f.Error = nil
		return nil
	}); err != nil {
		return err
	}
	dial := cfg.Dialer
	if dial == nil {
		dial = NewDialer(net.Dialer{})
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	runner := &HookRunner{Manager: cfg.Manager}
	replayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	pool := newServerPool(replayCtx, client, dial, runner, cfg.Manager.Do)
	defer func() { cancel(); err = errors.Join(err, pool.closeAll(context.WithoutCancel(ctx))) }()
	c := &layer.Context{Data: &hookdata.Context{Client: client, Server: server, Options: cfg.Options}, Record: Record, Hooks: runner, Pool: pool, Do: cfg.Manager.Do, HTTPFidelity: cfg.HTTPFidelity, Logger: logger.With("replay", id)}
	return run(replayCtx, c, f, httpMode)
}
