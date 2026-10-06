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
	"github.com/zchee/mitmproxy-go/tlsparse"
)

func init() {
	layer.Register(hookdata.LayerClientDTLS, func(_ *layer.Context, _ hookdata.LayerSpec, child layer.Layer) (layer.Layer, error) {
		return &clientDTLS{child: child}, nil
	})
}

type clientDTLS struct {
	child  layer.Layer
	server *dtlsServerState
}

// Kind implements [layer.Layer].
func (*clientDTLS) Kind() hookdata.LayerKind { return hookdata.LayerClientDTLS }

// Run implements [layer.Layer].
func (l *clientDTLS) Run(ctx context.Context, c *layer.Context) error {
	if c.ClientPackets == nil || c.RecordPackets == nil || c.ClientPackets.RemoteAddr() == nil {
		return errors.New("tlslayer: client DTLS requires a packet transport and recorder")
	}
	failureData := &hookdata.TLS{IsDTLS: true}
	if err := c.Do(ctx, func(context.Context) error {
		if c.Data.Client.TransportProtocol != connection.UDP {
			return errors.New("tlslayer: client DTLS requires UDP")
		}
		client := c.Data.Client
		if client.TLS {
			client.ALPN = nil
			client.ALPNOffers = nil
			client.CertificateList = nil
			client.Cipher = nil
			client.CipherList = nil
			client.MitmCert = nil
			client.SNI = nil
			client.TimestampTLSSetup = nil
			client.TLSVersion = ""
		}
		client.TLS = true
		failureData.Conn, failureData.Context = &client.Connection, c.Data
		return nil
	}); err != nil {
		return err
	}
	hello, err := readDTLSClientHello(ctx, c.ClientPackets, c.Clock)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, tlsparse.ErrTooLarge) || errors.Is(err, layer.ErrRecordSize) {
			c.Logger.InfoContext(ctx, "Cannot read the TLS ClientHello within mitmproxy's size limits, forwarding raw UDP.")
			return l.relayRaw(ctx, c)
		}
		return failDTLSHandshake(ctx, c, failureData, err)
	}
	helloData := &hookdata.ClientHello{ClientHello: hello}
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		helloData.Context = c.Data
		client := c.Data.Client
		if sni := hello.SNI(); sni != "" {
			client.SNI = &sni
		} else {
			client.SNI = nil
		}
		client.ALPNOffers = hello.ALPNProtocols()
		return nil
	}, addon.TLSClientHelloHook{Data: helloData}); err != nil {
		return err
	}
	if helloData.IgnoreConnection {
		return l.relayRaw(ctx, c)
	}
	if helloData.EstablishServerTLSFirst {
		if l.server == nil {
			c.Logger.InfoContext(ctx, "Unable to establish TLS connection with server (No server TLS available.). Trying to establish TLS with client anyway.")
		} else if err := l.startServer(ctx, c); err != nil {
			c.Logger.InfoContext(ctx, "Unable to establish TLS connection with server ("+err.Error()+"). Trying to establish TLS with client anyway.")
		}
	}
	data := &hookdata.TLS{IsDTLS: true}
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Context, data.Conn = c.Data, &c.Data.Client.Connection
		return nil
	}, addon.TLSStartClientHook{Data: data}); err != nil {
		return err
	}
	if err := c.Do(ctx, func(context.Context) error { return data.ValidateConfig() }); err != nil {
		return failDTLSHandshake(ctx, c, data, err)
	}
	raw := c.ClientPackets
	raw.StopRecording()
	// The frozen Config hook surface maps to pion's packet constructor.
	session, err := dtls.Server(raw, raw.RemoteAddr(), data.DTLSConfig) //nolint:staticcheck // The addon contract supplies *dtls.Config.
	if err != nil {
		return failDTLSHandshake(ctx, c, data, err)
	}
	defer func() { _ = session.Close() }()
	if err := session.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return failDTLSHandshake(ctx, c, data, err)
	}
	state, ok := session.ConnectionState()
	if !ok {
		return failDTLSHandshake(ctx, c, data, errors.New("tlslayer: client DTLS handshake returned no state"))
	}
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		publishDTLS(&c.Data.Client.Connection, &state)
		return nil
	}, addon.TLSEstablishedClientHook{Data: data}); err != nil {
		return err
	}
	c.ClientPackets = c.RecordPackets(&dtlsPackets{Conn: session, raw: raw})
	child := l.child
	if child == nil {
		if child, err = layer.Next(ctx, c); err != nil {
			return err
		}
	}
	return child.Run(ctx, c)
}

func (l *clientDTLS) startServer(ctx context.Context, c *layer.Context) error {
	var server *connection.Server
	if err := c.Do(ctx, func(context.Context) error {
		server = c.Data.Server
		return nil
	}); err != nil {
		return err
	}
	packets, actual, err := c.OpenPackets(ctx, server)
	if err != nil {
		return err
	}
	c.ServerPackets = c.RecordPackets(packets)
	return c.Do(ctx, func(context.Context) error {
		c.Data.Server = actual
		return nil
	})
}

func (l *clientDTLS) relayRaw(ctx context.Context, c *layer.Context) error {
	derived := *c
	derived.ClientPackets.StopRecording()
	if l.server != nil {
		derived.OpenPackets = l.server.openRaw
		derived.ServerPackets = l.server.raw
	}
	child, err := layer.Build(ctx, &derived, hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: true}})
	if err != nil {
		return err
	}
	return child.Run(ctx, &derived)
}
