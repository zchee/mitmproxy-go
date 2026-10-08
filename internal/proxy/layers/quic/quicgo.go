// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"

	quicgo "github.com/quic-go/quic-go"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
	"github.com/zchee/mitmproxy-go/udp"
)

// ConnectionConsumer borrows established QUIC endpoints until RunQUIC returns.
// It exclusively owns their stream and datagram I/O and may reset streams.
// It may CloseWithError only for a protocol/application abort, returning that
// error. Normal connection shutdown and Transport/socket ownership stay with
// RawQuicLayer; consumers must retain nothing after returning.
type ConnectionConsumer interface {
	RunQUIC(ctx context.Context, c *layer.Context, client, server *quicgo.Conn) error
}

type quicSession struct {
	transport *quicgo.Transport
	listener  *quicgo.Listener
	conn      *quicgo.Conn
}

func (s *quicSession) close() {
	if s.conn != nil {
		_ = s.conn.CloseWithError(0, "")
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	// Transport.Close interrupts and joins its reader but does not close the
	// caller-supplied PacketConn (quic-go transport.go Close).
	if s.transport != nil {
		_ = s.transport.Close()
	}
}

func (l *RawQuicLayer) runQUIC(ctx context.Context, c *layer.Context, serverFirst bool) error {
	var client, server quicSession
	defer client.close()
	defer server.close()
	defer func() {
		for _, pair := range [][2]*quicgo.Conn{{client.conn, server.conn}, {server.conn, client.conn}} {
			if pair[0] == nil || pair[1] == nil {
				continue
			}
			if closed, ok := errors.AsType[*quicgo.ApplicationError](context.Cause(pair[0].Context())); ok && closed.Remote {
				_ = pair[1].CloseWithError(closed.ErrorCode, closed.ErrorMessage)
			}
		}
	}()
	var serverErr error
	if serverFirst {
		serverErr = startServer(ctx, c, &server)
		if serverErr != nil && c.Logger != nil {
			c.Logger.InfoContext(ctx, "Unable to establish QUIC connection with server ("+serverErr.Error()+"). Trying to establish QUIC with client anyway. If you plan to redirect requests away from this server, consider setting `connection_strategy` to `lazy` to suppress early connections.")
		}
	}
	policy, err := startPolicy(ctx, c, true)
	if err != nil {
		return handshakeFailed(ctx, c, true, err)
	}
	conf, err := policy.config(true)
	if err != nil {
		return handshakeFailed(ctx, c, true, err)
	}
	c.ClientPackets.StopRecording()
	client.transport = &quicgo.Transport{Conn: c.ClientPackets}
	client.listener, err = client.transport.Listen(conf, transportConfig())
	if err == nil {
		client.conn, err = client.listener.Accept(ctx)
	}
	if err != nil {
		return handshakeFailed(ctx, c, true, err)
	}
	if err := established(ctx, c, client.conn, true); err != nil {
		return err
	}
	if serverErr != nil {
		return serverErr
	}
	if server.conn == nil {
		if err := startServer(ctx, c, &server); err != nil {
			return err
		}
	}
	consumerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopClient := context.AfterFunc(client.conn.Context(), cancel)
	stopServer := context.AfterFunc(server.conn.Context(), cancel)
	defer stopClient()
	defer stopServer()
	if l.consumer != nil {
		err = l.consumer.RunQUIC(consumerCtx, c, client.conn, server.conn)
	} else {
		err = relayQUIC(consumerCtx, c, client.conn, server.conn)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	for _, conn := range []*quicgo.Conn{client.conn, server.conn} {
		if cause := context.Cause(conn.Context()); cause != nil {
			if app, ok := errors.AsType[*quicgo.ApplicationError](cause); ok && app.ErrorCode == 0 {
				return nil
			}
			return cause
		}
	}
	return err
}

func transportConfig() *quicgo.Config {
	return &quicgo.Config{EnableDatagrams: true, MaxIncomingStreams: 100, MaxIncomingUniStreams: 100}
}

func startServer(ctx context.Context, c *layer.Context, session *quicSession) error {
	var metadata *connection.Server
	if err := c.Do(ctx, func(context.Context) error { metadata = c.Data.Server; return nil }); err != nil {
		return err
	}
	if c.ServerPackets == nil {
		packets, actual, err := c.OpenPackets(ctx, metadata)
		if err != nil {
			return err
		}
		c.ServerPackets = c.RecordPackets(packets)
		if err := c.Do(ctx, func(context.Context) error { c.Data.Server = actual; actual.TLS = true; return nil }); err != nil {
			return err
		}
	}
	policy, err := startPolicy(ctx, c, false)
	if err != nil {
		return handshakeFailed(ctx, c, false, err)
	}
	conf, err := policy.config(false)
	if err != nil {
		return handshakeFailed(ctx, c, false, err)
	}
	c.ServerPackets.StopRecording()
	session.transport = &quicgo.Transport{Conn: c.ServerPackets}
	session.conn, err = session.transport.Dial(ctx, c.ServerPackets.RemoteAddr(), conf, transportConfig())
	if err != nil {
		return handshakeFailed(ctx, c, false, err)
	}
	return established(ctx, c, session.conn, false)
}

func established(ctx context.Context, c *layer.Context, conn *quicgo.Conn, client bool) error {
	state := conn.ConnectionState().TLS
	data := &hookdata.TLS{}
	var hook addon.Hook = addon.TLSEstablishedServerHook{Data: data}
	if client {
		hook = addon.TLSEstablishedClientHook{Data: data}
	}
	_, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
		data.Context, data.Conn = c.Data, &c.Data.Server.Connection
		if client {
			data.Conn = &c.Data.Client.Connection
		}
		data.Conn.TimestampTLSSetup = new(stateutil.Now())
		data.Conn.ALPN, data.Conn.TLSVersion = []byte(state.NegotiatedProtocol), connection.QUICv1
		data.Conn.Cipher = new(strings.TrimPrefix(tls.CipherSuiteName(state.CipherSuite), "TLS_"))
		for i, cipher := range data.Conn.CipherList {
			data.Conn.CipherList[i] = strings.TrimPrefix(cipher, "TLS_")
		}
		data.Conn.CertificateList = nil
		for _, cert := range state.PeerCertificates {
			data.Conn.CertificateList = append(data.Conn.CertificateList, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
		return nil
	}, hook)
	return err
}

func streamResetCode(err error) (uint64, bool) {
	if reset, ok := errors.AsType[*quicgo.StreamError](err); ok {
		return uint64(reset.ErrorCode), true
	}
	return 0, false
}

func bidirectional(s *quicgo.Stream) streamSide {
	return streamSide{read: &readHalf{Reader: s, peek: s.Peek, cancel: func(code uint64) { s.CancelRead(quicgo.StreamErrorCode(code)) }}, write: &writeHalf{WriteCloser: s, cancel: func(code uint64) { s.CancelWrite(quicgo.StreamErrorCode(code)) }, ctx: s.Context()}, id: int64(s.StreamID())}
}

func receiveOnly(s *quicgo.ReceiveStream) streamSide {
	return streamSide{read: &readHalf{Reader: s, peek: s.Peek, cancel: func(code uint64) { s.CancelRead(quicgo.StreamErrorCode(code)) }}, id: int64(s.StreamID())}
}

func sendOnly(s *quicgo.SendStream) streamSide {
	return streamSide{write: &writeHalf{WriteCloser: s, cancel: func(code uint64) { s.CancelWrite(quicgo.StreamErrorCode(code)) }, ctx: s.Context()}, id: int64(s.StreamID())}
}

type acceptedStream struct {
	client, server streamSide
	fromClient     bool
	err            error
}

func relayQUIC(ctx context.Context, c *layer.Context, client, server *quicgo.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	accepted := make(chan acceptedStream)
	finished := make(chan string, 100)
	slots := make(chan struct{}, 100)
	var workers sync.WaitGroup
	// One acceptor per endpoint and stream direction; wire admission is also
	// bounded by quic-go, while slots bounds their combined active owners.
	for _, source := range []struct {
		conn, target    *quicgo.Conn
		fromClient, uni bool
	}{{client, server, true, false}, {client, server, true, true}, {server, client, false, false}, {server, client, false, true}} {
		workers.Go(func() {
			for {
				var event acceptedStream
				var incoming streamSide
				if source.uni {
					stream, err := source.conn.AcceptUniStream(ctx)
					if err != nil {
						return
					}
					incoming = receiveOnly(stream)
				} else {
					stream, err := source.conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					incoming = bidirectional(stream)
				}
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					incoming.read.cancel(0)
					return
				}
				workers.Go(func() {
					// Implicit lower stream IDs must not reserve origin IDs or
					// create flows before actual data, FIN or reset is received.
					interrupted := make(chan struct{})
					stop := context.AfterFunc(ctx, func() { incoming.read.cancel(0); close(interrupted) })
					var first [1]byte
					_, peekErr := incoming.read.peek(first[:])
					if !stop() {
						<-interrupted
					}
					if ctx.Err() != nil {
						return
					}
					var outgoing streamSide
					_, reset := streamResetCode(peekErr)
					if peekErr != nil && !errors.Is(peekErr, io.EOF) && !reset {
						event.err = peekErr
					} else if source.uni {
						stream, err := source.target.OpenUniStreamSync(ctx)
						event.err = err
						if err == nil {
							outgoing = sendOnly(stream)
						}
					} else {
						stream, err := source.target.OpenStreamSync(ctx)
						event.err = err
						if err == nil {
							outgoing = bidirectional(stream)
						}
					}
					event.client, event.server, event.fromClient = incoming, outgoing, source.fromClient
					if !source.fromClient {
						event.client, event.server = outgoing, incoming
					}
					select {
					case accepted <- event:
					case <-ctx.Done():
						incoming.read.cancel(0)
					}
				})
			}
		})
	}
	defer func() { cancel(); workers.Wait() }()
	routes := make(map[string]chan layer.Injected)
	dgrams, err := newDatagrams(ctx, c, client, server)
	if err != nil {
		return err
	}
	dgramInject := make(chan layer.Injected, layer.InjectionCapacity)
	processed := make(chan struct{}, layer.InjectionCapacity)
	pending := 0
	dgrams.injectionDone = processed
	routes[dgrams.flow.ID] = dgramInject
	dgramDone := make(chan error, 1)
	workers.Go(func() { dgramDone <- dgrams.run(ctx, c, dgramInject) })
	inject := c.Inject
	for {
		// Demultiplexing must not multiply the connection-wide injection bound.
		admitted := inject
		if pending == layer.InjectionCapacity {
			admitted = nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-dgramDone:
			return err
		case <-processed:
			pending--
		case id := <-finished:
			pending -= len(routes[id])
			delete(routes, id)
			<-slots
		case msg, ok := <-admitted:
			if !ok {
				inject = nil
				continue
			}
			if route := routes[msg.FlowID]; route != nil {
				route <- msg
				pending++
			}
		case event := <-accepted:
			if event.err != nil {
				return event.err
			}
			stream, child, err := newStream(ctx, c, event)
			if err != nil {
				return err
			}
			messages := make(chan layer.Injected, layer.InjectionCapacity)
			stream.injectionDone = processed
			routes[stream.flow.ID], stream.injected = messages, messages
			id := stream.flow.ID
			workers.Go(func() {
				stopClient := observeStop(stream.client.write, stream.server.read)
				stopServer := observeStop(stream.server.write, stream.client.read)
				defer stopClient()
				defer stopServer()
				if err := stream.Run(ctx, child); err != nil && ctx.Err() == nil && c.Logger != nil {
					c.Logger.DebugContext(ctx, "QUIC stream ended", "error", err)
				}
				select {
				case finished <- id:
				case <-ctx.Done():
				}
			})
		}
	}
}

func observeStop(dst *writeHalf, src *readHalf) func() {
	if dst == nil || src == nil {
		return func() {}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(dst.ctx, func() {
		defer close(done)
		if reset, ok := errors.AsType[*quicgo.StreamError](context.Cause(dst.ctx)); ok && reset.Remote {
			src.cancel(uint64(reset.ErrorCode))
		}
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

func newStream(ctx context.Context, c *layer.Context, event acceptedStream) (*QuicStreamLayer, *layer.Context, error) {
	stream := &QuicStreamLayer{client: event.client, server: event.server}
	child := *c
	err := c.Do(ctx, func(context.Context) error {
		data := *c.Data
		data.Client = c.Data.Client.Clone()
		data.Server = connection.NewServer(c.Data.Server.Clone().Address)
		data.Server.TimestampStart = new(stateutil.Now())
		data.Client.TransportProtocol, data.Server.TransportProtocol = connection.TCP, connection.TCP
		data.Client.State, data.Server.State = connection.Open, connection.Open
		uni := event.client.read == nil || event.client.write == nil
		if uni {
			data.Client.State, data.Server.State = connection.CanRead, connection.CanWrite
			if !event.fromClient {
				data.Client.State, data.Server.State = connection.CanWrite, connection.CanRead
			}
		}
		stream.flow = flow.NewTCPFlow(data.Client, data.Server, true)
		stream.flow.Metadata.Set("quic_is_unidirectional", uni)
		initiator := "server"
		if event.fromClient {
			initiator = "client"
		}
		stream.flow.Metadata.Set("quic_initiator", initiator)
		stream.flow.Metadata.Set("quic_stream_id_client", event.client.id)
		stream.flow.Metadata.Set("quic_stream_id_server", event.server.id)
		data.Layers = append(slices.Clone(c.Data.Layers), stream)
		child.Data = &data
		return nil
	})
	return stream, &child, err
}

type datagrams struct {
	flow           *flow.UDPFlow
	client, server *quicgo.Conn
	injectionDone  chan<- struct{}
}

func newDatagrams(ctx context.Context, c *layer.Context, client, server *quicgo.Conn) (*datagrams, error) {
	d := &datagrams{client: client, server: server}
	err := c.Do(ctx, func(context.Context) error { d.flow = flow.NewUDPFlow(c.Data.Client, c.Data.Server, true); return nil })
	return d, err
}

func (d *datagrams) run(ctx context.Context, c *layer.Context, inject <-chan layer.Injected) (result error) {
	defer func() {
		endCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), layer.TerminalHookTimeout)
		defer cancel()
		var hook addon.Hook = addon.UDPEndHook{Flow: d.flow}
		failed := result != nil && ctx.Err() == nil && !errors.Is(result, net.ErrClosed)
		if failed {
			hook = addon.UDPErrorHook{Flow: d.flow}
		}
		_, err := c.Hooks.FireFunc(endCtx, func(context.Context) error {
			if failed {
				d.flow.Error = flow.NewError(result.Error())
			}
			return nil
		}, hook)
		endErr := c.Do(endCtx, func(context.Context) error { d.flow.Live = false; return nil })
		result = errors.Join(result, err, endErr)
	}()
	if _, err := c.Hooks.Fire(ctx, addon.UDPStartHook{Flow: d.flow}); err != nil {
		return err
	}
	type packet struct {
		content    []byte
		fromClient bool
		err        error
	}
	incoming := make(chan packet)
	readCtx, cancel := context.WithCancel(ctx)
	var readers sync.WaitGroup
	defer func() { cancel(); readers.Wait() }()
	for _, source := range []struct {
		conn       *quicgo.Conn
		fromClient bool
	}{{d.client, true}, {d.server, false}} {
		readers.Go(func() {
			for {
				data, err := source.conn.ReceiveDatagram(readCtx)
				select {
				case incoming <- packet{data, source.fromClient, err}:
				case <-readCtx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		})
	}
	injectedActive := false
	defer func() {
		if injectedActive {
			notifyInjection(ctx, d.injectionDone)
		}
	}()
	for {
		var event packet
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event = <-incoming:
		case msg, ok := <-inject:
			if !ok {
				inject = nil
				continue
			}
			m, ok := msg.Message.(*udp.Message)
			if !ok || m == nil {
				notifyInjection(ctx, d.injectionDone)
				continue
			}
			injectedActive = true
			event = packet{content: m.Content, fromClient: m.FromClient}
		}
		if event.err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return event.err
		}
		snapshot, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
			d.flow.Messages = append(d.flow.Messages, udp.NewMessage(event.fromClient, event.content))
			return nil
		}, addon.UDPMessageHook{Flow: d.flow})
		if err != nil {
			return err
		}
		if snapshot.Killed() {
			return nil
		}
		if snapshot.LastUDPMessage == nil {
			if injectedActive {
				notifyInjection(ctx, d.injectionDone)
				injectedActive = false
			}
			continue
		}
		dst := d.server
		if !event.fromClient {
			dst = d.client
		}
		if err := dst.SendDatagram(snapshot.LastUDPMessage.Content); err != nil {
			return fmt.Errorf("quic: send datagram: %w", err)
		}
		if injectedActive {
			notifyInjection(ctx, d.injectionDone)
			injectedActive = false
		}
	}
}
