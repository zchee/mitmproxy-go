// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes

import (
	"context"
	"errors"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func init() {
	layer.Register("wireguard", newDestinationMode)
	layer.Register("tun", newDestinationMode)
}

type destinationMode struct{ kind hookdata.LayerKind }

func newDestinationMode(_ *layer.Context, spec hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
	return &destinationMode{kind: spec.Kind}, nil
}

// Kind returns the packet-source mode's top-layer identity.
func (m *destinationMode) Kind() hookdata.LayerKind { return m.kind }

// Run selects a transparent protocol layer using the already captured destination.
func (m *destinationMode) Run(ctx context.Context, c *layer.Context) error {
	var server *connection.Server
	if err := c.Do(ctx, func(context.Context) error {
		if c.Data.Server.Address == nil {
			return errors.New("packet source has no destination address")
		}
		if c.Data.Options.Str("connection_strategy") == "eager" && c.Data.Server.TransportProtocol == connection.TCP {
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
		if err := c.Do(ctx, func(context.Context) error { c.Data.Server = actual; return nil }); err != nil {
			return err
		}
	}
	child, err := layer.Next(ctx, c)
	if err != nil {
		return err
	}
	return child.Run(ctx, c)
}
