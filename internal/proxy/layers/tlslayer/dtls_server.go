// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"context"
	"errors"

	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func init() {
	layer.Register(hookdata.LayerServerDTLS, func(_ *layer.Context, _ hookdata.LayerSpec, child layer.Layer) (layer.Layer, error) {
		return &serverDTLS{child: child}, nil
	})
}

type serverDTLS struct {
	child layer.Layer
}

// Kind implements [layer.Layer].
func (*serverDTLS) Kind() hookdata.LayerKind { return hookdata.LayerServerDTLS }

// Run implements [layer.Layer].
func (l *serverDTLS) Run(ctx context.Context, c *layer.Context) error {
	if c.RecordPackets == nil || (c.OpenPackets == nil && c.ServerPackets == nil) {
		return errors.New("tlslayer: server DTLS requires a packet transport and recorder")
	}
	if c.ClientPackets != nil {
		first, _, err := c.ClientPackets.PeekPacket()
		if err != nil {
			return err
		}
		// A late record can recreate an evicted tuple, but cannot start a new
		// DTLS session. Do not turn its readmission into an origin handshake.
		if len(first) >= 3 && first[1] == 0xfe && (first[2] == 0xfd || first[2] == 0xfe) && (first[0] == 20 || first[0] == 21 || first[0] == 23) {
			c.Logger.InfoContext(ctx, "Discarding DTLS record without an initial ClientHello.")
			return nil
		}
	}
	state := &dtlsServerState{c: c, raw: c.ServerPackets, openRaw: c.OpenPackets}
	if err := c.Do(ctx, func(context.Context) error {
		if c.Data.Server.TransportProtocol != connection.UDP {
			return errors.New("tlslayer: server DTLS requires UDP")
		}
		c.Data.Server.TLS = true
		state.initial = c.Data.Server
		return nil
	}); err != nil {
		return err
	}
	derived := *c
	derived.OpenPackets = state.open
	defer func() {
		for _, session := range state.sessions {
			_ = session.Close()
		}
	}()
	child := l.child
	if child == nil {
		var err error
		if child, err = layer.Next(ctx, &derived); err != nil {
			return err
		}
	}
	if client, ok := child.(*clientDTLS); ok {
		// Keep the layer instance immutable; this connection's child owns the
		// deferred server state, including bypassing it for ignore_connection.
		copy := *client
		copy.server = state
		child = &copy
		derived.ServerPackets = nil
	} else if state.raw != nil {
		packets, actual, err := state.open(ctx, state.initial)
		if err != nil {
			return err
		}
		derived.ServerPackets = c.RecordPackets(packets)
		if err := c.Do(ctx, func(context.Context) error {
			c.Data.Server = actual
			return nil
		}); err != nil {
			return err
		}
	}
	return child.Run(ctx, &derived)
}

// One connection's flow owner calls open; the handler continues owning the raw
// transport. Sessions are scoped to Run and close before that handler returns.
type dtlsServerState struct {
	c        *layer.Context
	raw      layer.PacketRecorder
	initial  *connection.Server
	openRaw  func(context.Context, *connection.Server) (layer.PacketTransport, *connection.Server, error)
	current  *dtlsPackets
	actual   *connection.Server
	sessions []*dtlsPackets
}

func (p *dtlsServerState) open(ctx context.Context, server *connection.Server) (layer.PacketTransport, *connection.Server, error) {
	if p.current != nil && server == p.actual {
		return p.current, p.actual, nil
	}
	var raw layer.PacketTransport
	actual := server
	if p.raw != nil && server == p.initial {
		p.raw.StopRecording()
		raw = p.raw
		p.raw = nil
	} else {
		if p.openRaw == nil {
			return nil, nil, errors.New("tlslayer: no server packet opener")
		}
		var err error
		if raw, actual, err = p.openRaw(ctx, server); err != nil {
			return nil, nil, err
		}
	}
	if raw == nil || actual == nil || raw.RemoteAddr() == nil {
		return nil, nil, errors.New("tlslayer: server DTLS opener returned no packet transport or metadata")
	}
	data := &hookdata.TLS{IsDTLS: true}
	if _, err := p.c.Hooks.FireFunc(ctx, func(context.Context) error {
		if actual.TransportProtocol != connection.UDP {
			return errors.New("tlslayer: server DTLS requires UDP")
		}
		hookContext := *p.c.Data
		hookContext.Server = actual
		data.Context, data.Conn = &hookContext, &actual.Connection
		actual.TLS = true
		return nil
	}, addon.TLSStartServerHook{Data: data}); err != nil {
		return nil, nil, err
	}
	if err := p.c.Do(ctx, func(context.Context) error { return data.ValidateConfig() }); err != nil {
		return nil, nil, failDTLSHandshake(ctx, p.c, data, err)
	}
	session, err := dtls.Client(raw, raw.RemoteAddr(), data.DTLSConfig) //nolint:staticcheck // The addon contract supplies *dtls.Config.
	if err != nil {
		return nil, nil, failDTLSHandshake(ctx, p.c, data, err)
	}
	packets := &dtlsPackets{Conn: session, raw: raw}
	p.sessions = append(p.sessions, packets)
	if err := session.HandshakeContext(ctx); err != nil {
		return nil, nil, failDTLSHandshake(ctx, p.c, data, err)
	}
	state, ok := session.ConnectionState()
	if !ok {
		return nil, nil, failDTLSHandshake(ctx, p.c, data, errors.New("tlslayer: server DTLS handshake returned no state"))
	}
	if _, err := p.c.Hooks.FireFunc(ctx, func(context.Context) error {
		publishDTLS(&actual.Connection, &state)
		return nil
	}, addon.TLSEstablishedServerHook{Data: data}); err != nil {
		return nil, nil, err
	}
	p.current, p.actual = packets, actual
	return packets, actual, nil
}
