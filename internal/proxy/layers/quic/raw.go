// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package quic intercepts QUIC connections and relays their streams and datagrams.
package quic

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tlsparse"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/udplayer"
)

func init() {
	layer.Register("quic", func(_ *layer.Context, _ hookdata.LayerSpec, child layer.Layer) (layer.Layer, error) {
		if child != nil {
			return nil, errors.New("quic: raw connection does not accept a byte-stream child")
		}
		return NewRawQuicLayer(nil), nil
	})
}

// RawQuicLayer owns interception handshakes and per-flow QUIC transports.
// The underlying packet transports remain owned by the connection handler.
// A consumer borrows established endpoints until it returns; nil selects raw relay.
// QUIC TLS hook installers must not mutate private-key internals after installation;
// snapshots share immutable signing material, including opaque crypto.Signers.
type RawQuicLayer struct {
	consumer     ConnectionConsumer
	modifyConfig quicConfigModifier
}

// NewRawQuicLayer returns an interception layer with the given endpoint consumer.
// A nil consumer relays streams through TCP hooks and datagrams through UDP hooks.
func NewRawQuicLayer(consumer ConnectionConsumer) *RawQuicLayer {
	return &RawQuicLayer{consumer: consumer}
}

// Kind identifies the upstream RawQuicLayer marker.
func (*RawQuicLayer) Kind() hookdata.LayerKind { return "quic" }

// Run intercepts one packet-preserving client connection, then joins its consumer.
// Cancellation interrupts handshakes and returns the caller's cancellation error.
func (l *RawQuicLayer) Run(ctx context.Context, c *layer.Context) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || c.Data == nil || c.Do == nil || c.Hooks == nil || c.ClientPackets == nil || c.RecordPackets == nil || c.OpenPackets == nil {
		return errors.New("quic: interception requires a packet context")
	}
	defer func() {
		if ctx.Err() != nil {
			result = ctx.Err()
		}
	}()
	if err := c.Do(ctx, func(context.Context) error {
		if c.Data.Client == nil || c.Data.Server == nil || c.Data.Client.TransportProtocol != connection.UDP {
			return errors.New("quic: interception requires UDP metadata")
		}
		client := c.Data.Client
		if client.TLS {
			client.ALPN, client.ALPNOffers = nil, nil
			client.CertificateList, client.CipherList = nil, nil
			client.Cipher, client.SNI, client.TimestampTLSSetup = nil, nil, nil
			client.MitmCert, client.TLSVersion = nil, ""
		}
		client.TLS, c.Data.Server.TLS = true, true
		return nil
	}); err != nil {
		return err
	}
	hello, err := readHello(ctx, c.ClientPackets, c.Clock)
	if err != nil {
		if errors.Is(err, tlsparse.ErrTooLarge) || errors.Is(err, layer.ErrRecordSize) {
			return relayIgnored(ctx, c)
		}
		return handshakeFailed(ctx, c, true, err)
	}
	data := &hookdata.ClientHello{ClientHello: hello}
	if _, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Context = c.Data
		client := c.Data.Client
		if sni := hello.SNI(); sni != "" {
			client.SNI = new(sni)
		}
		client.ALPNOffers = hello.ALPNProtocols()
		return nil
	}, addon.TLSClientHelloHook{Data: data}); err != nil {
		return err
	}
	var ignore, serverFirst bool
	if err := c.Do(ctx, func(context.Context) error {
		ignore, serverFirst = data.IgnoreConnection, data.EstablishServerTLSFirst
		return nil
	}); err != nil {
		return err
	}
	if ignore {
		return relayIgnored(ctx, c)
	}
	return l.runQUIC(ctx, c, serverFirst)
}

func relayIgnored(ctx context.Context, c *layer.Context) error {
	derived := *c
	child, err := layer.Build(ctx, &derived, hookdata.LayerStack{{Kind: hookdata.LayerUDP, Ignore: true}})
	if err != nil {
		return err
	}
	return child.Run(ctx, &derived)
}

func readHello(ctx context.Context, conn layer.PacketTransport, clock layer.Clock) (hello *tlsparse.ClientHello, result error) {
	if clock == nil {
		clock = layer.WallClock
	}
	var expired atomic.Bool
	timedOut, cancelled := make(chan struct{}), make(chan struct{})
	stopTimer := clock.AfterFunc(layer.HeadReadTimeout, func() {
		expired.Store(true)
		_ = conn.SetReadDeadline(time.Unix(1, 0))
		close(timedOut)
	})
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Unix(1, 0))
		close(cancelled)
	})
	defer func() {
		if !stopTimer() {
			<-timedOut
		}
		if !stopCancel() {
			<-cancelled
		}
		_ = conn.SetReadDeadline(time.Time{})
		if ctx.Err() != nil {
			hello, result = nil, ctx.Err()
		} else if expired.Load() {
			hello, result = nil, os.ErrDeadlineExceeded
		}
	}()
	var parser tlsparse.QUICClientHelloParser
	buf := make([]byte, layer.MaxUDPPacketBytes+1)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		hello, err = parser.Feed(buf[:n])
		if hello != nil || err != nil {
			return hello, err
		}
	}
}

func handshakeFailed(ctx context.Context, c *layer.Context, client bool, failure error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	data := &hookdata.TLS{}
	var hook addon.Hook = addon.TLSFailedServerHook{Data: data}
	name := "Server"
	if client {
		hook, name = addon.TLSFailedClientHook{Data: data}, "Client"
	}
	if c.Logger != nil {
		c.Logger.WarnContext(ctx, fmt.Sprintf("%s QUIC handshake failed. %v", name, failure))
	}
	_, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Context = c.Data
		data.Conn = &c.Data.Server.Connection
		if client {
			data.Conn = &c.Data.Client.Connection
		}
		data.Conn.Error = new(failure.Error())
		return nil
	}, hook)
	return errors.Join(failure, err)
}
