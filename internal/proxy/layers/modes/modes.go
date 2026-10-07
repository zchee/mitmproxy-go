// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package modes registers the regular, reverse, and upstream proxy top layers.
// Protocol selection, HTTP forwarding, and TLS wrapping belong to their children.
package modes

import (
	"context"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func init() {
	layer.Register(hookdata.LayerRegular, newMode)
	layer.Register(hookdata.LayerReverse, newMode)
	layer.Register(hookdata.LayerUpstream, newMode)
}

type mode struct {
	kind    hookdata.LayerKind
	reverse reverseScheme
}

func newMode(c *layer.Context, spec hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
	m := &mode{kind: spec.Kind}
	if spec.Kind == hookdata.LayerReverse {
		entry, err := configureReverse(c)
		if err != nil {
			return nil, err
		}
		m.reverse = entry
	}
	return m, nil
}

// Kind returns the proxy mode's registered layer kind.
func (m *mode) Kind() hookdata.LayerKind { return m.kind }

// Run opens an eager reverse connection when configured and runs the selected child layer.
func (m *mode) Run(ctx context.Context, c *layer.Context) error {
	if m.kind == hookdata.LayerReverse {
		var server *connection.Server
		if err := c.Do(ctx, func(context.Context) error {
			if m.reverse.connectEagerly(c) {
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
