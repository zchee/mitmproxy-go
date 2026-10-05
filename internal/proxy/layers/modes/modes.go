// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package modes registers the regular, reverse, and upstream proxy top layers.
// Protocol selection, HTTP forwarding, and TLS wrapping belong to their children.
package modes

import (
	"context"
	"fmt"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func init() {
	layer.Register(hookdata.LayerRegular, newMode)
	layer.Register(hookdata.LayerReverse, newMode)
	layer.Register(hookdata.LayerUpstream, newMode)
}

type mode struct {
	kind hookdata.LayerKind
}

func newMode(c *layer.Context, spec hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
	if spec.Kind == hookdata.LayerReverse {
		parsed, err := modespec.Parse(c.Data.Client.ProxyMode)
		if err != nil {
			return nil, err
		}
		reverse, ok := parsed.(modespec.ReverseMode)
		if !ok {
			return nil, fmt.Errorf("modes: reverse layer requires a reverse proxy mode")
		}
		switch reverse.Scheme {
		case "http", "https", "tls", "tcp":
		case "udp", "dtls":
			return nil, fmt.Errorf("modes: reverse scheme %q requires datagram transport support", reverse.Scheme)
		case "http3", "quic", "dns":
			return nil, fmt.Errorf("modes: reverse scheme %q requires QUIC and DNS protocol support", reverse.Scheme)
		default:
			return nil, fmt.Errorf("modes: unsupported reverse scheme %q", reverse.Scheme)
		}
		c.Data.Server.Address = &connection.Address{Host: reverse.Address.Host, Port: reverse.Address.Port}
		if (reverse.Scheme == "https" || reverse.Scheme == "tls") && !c.Data.Options.Bool("keep_host_header") {
			c.Data.Server.SNI = new(reverse.Address.Host)
		}
	}
	return &mode{kind: spec.Kind}, nil
}

// Kind returns the proxy mode's registered layer kind.
func (m *mode) Kind() hookdata.LayerKind { return m.kind }

// Run opens an eager reverse connection when configured and runs the selected child layer.
func (m *mode) Run(ctx context.Context, c *layer.Context) error {
	if m.kind == hookdata.LayerReverse {
		var server *connection.Server
		if err := c.Do(ctx, func(context.Context) error {
			if c.Data.Options.Str("connection_strategy") == "eager" && c.Data.Server.Address != nil && c.Data.Server.TransportProtocol == connection.TCP {
				server = c.Data.Server
			}
			return nil
		}); err != nil {
			return err
		}
		if server != nil {
			conn, actual, err := c.Pool.Open(ctx, server, layer.OpenOptions{Reuse: true})
			if err != nil {
				return err
			}
			c.Server = c.Record(conn)
			if err := c.Do(ctx, func(context.Context) error {
				c.Data.Server = actual
				return nil
			}); err != nil {
				return err
			}
		}
	}
	child, err := layer.Next(ctx, c)
	if err != nil {
		return err
	}
	return child.Run(ctx, c)
}
