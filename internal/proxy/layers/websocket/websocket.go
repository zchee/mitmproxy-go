// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package websocket relays upgraded HTTP connections through serial WebSocket hooks.
package websocket

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"unicode/utf8"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	wsmodel "github.com/zchee/mitmproxy-go/websocket"
)

const maxFragmentsPerMessage = 65536

// Config supplies an HTTP 101 handoff. Buffered bytes must have been consumed
// from the HTTP readers; New copies them and each prefix is replayed only once.
// Offer and response slices contain the actual extension header lines of each
// independent handshake, not a shared compression policy for both peers.
type Config struct {
	Flow                                                     *flow.HTTPFlow
	Client, Server                                           net.Conn
	ClientBuffered, ServerBuffered                           []byte
	ClientOffer, ClientResponse, ServerOffer, ServerResponse []string
}

// New validates both extension negotiations and builds a frame-mode relay.
// It neither performs I/O nor changes the flow; Run owns lifecycle mutations.
// Missing flow/transports or invalid response extensions return an error.
func New(cfg Config) (layer.Layer, error) {
	if cfg.Flow == nil || cfg.Client == nil || cfg.Server == nil {
		return nil, errors.New("websocket: handoff requires an HTTP flow and both transports")
	}
	clientParams, clientCompressed, err := gows.ParseCompression(cfg.ClientOffer, cfg.ClientResponse)
	if err != nil {
		return nil, fmt.Errorf("websocket: client negotiation: %w", err)
	}
	serverParams, serverCompressed, err := gows.ParseCompression(cfg.ServerOffer, cfg.ServerResponse)
	if err != nil {
		return nil, fmt.Errorf("websocket: server negotiation: %w", err)
	}
	clientOptions := []gows.ConnOption{gows.WithBuffered(cfg.ClientBuffered)}
	serverOptions := []gows.ConnOption{gows.WithBuffered(cfg.ServerBuffered)}
	if clientCompressed {
		clientOptions = append(clientOptions, gows.WithCompressionParams(clientParams))
	}
	if serverCompressed {
		serverOptions = append(serverOptions, gows.WithCompressionParams(serverParams))
	}
	return &relay{flow: cfg.Flow, client: gows.NewServerConn(cfg.Client, clientOptions...), server: gows.NewClientConn(cfg.Server, serverOptions...), clientCompressed: clientCompressed, serverCompressed: serverCompressed}, nil
}

type relay struct {
	flow                               *flow.HTTPFlow
	client, server                     *gows.Conn
	clientCompressed, serverCompressed bool
}

func (*relay) Kind() hookdata.LayerKind { return hookdata.LayerWebSocket }

func (r *relay) Run(ctx context.Context, c *layer.Context) error {
	if c == nil || c.Hooks == nil || c.Do == nil {
		return errors.New("websocket: Run requires hooks and dispatch")
	}
	clock := c.Clock
	if clock == nil {
		clock = layer.WallClock
	}
	terminal, err := r.run(ctx, c, clock)
	_ = r.client.Abort()
	_ = r.server.Abort()
	endCtx := context.WithoutCancel(ctx)
	if !terminal.recorded {
		err = errors.Join(err, r.recordEnd(endCtx, c, clock, terminal, err))
	}
	if err != nil {
		err = errors.Join(err, c.Do(endCtx, func(context.Context) error {
			r.flow.Error = flow.NewError(err.Error())
			return nil
		}))
	}
	_, hookErr := c.Hooks.Fire(endCtx, addon.WebSocketEndHook{Flow: r.flow})
	finishErr := c.Do(endCtx, func(context.Context) error { r.flow.Live = false; return nil })
	return errors.Join(err, hookErr, finishErr)
}

func (r *relay) recordEnd(ctx context.Context, c *layer.Context, clock layer.Clock, terminal received, err error) error {
	return c.Do(context.WithoutCancel(ctx), func(context.Context) error {
		if r.flow.WebSocket == nil {
			r.flow.WebSocket = &wsmodel.Data{}
		}
		r.flow.WebSocket.TimestampEnd = new(float64(clock.Now().UnixNano()) / 1e9)
		if terminal.op == gows.OpcodeClose {
			closeInfo, parseErr := gows.ParseClose(terminal.content)
			if parseErr != nil {
				return parseErr
			}
			r.flow.WebSocket.ClosedByClient = new(terminal.fromClient)
			r.flow.WebSocket.CloseCode = nil
			if len(terminal.content) > 0 {
				r.flow.WebSocket.CloseCode = new(int(closeInfo.Code))
			}
			r.flow.WebSocket.CloseReason = new(closeInfo.Reason)
		} else if err != nil {
			r.flow.Error = flow.NewError(err.Error())
			r.flow.WebSocket.CloseCode = new(int(gows.CloseAbnormalClosure))
			if terminal.err != nil {
				r.flow.WebSocket.ClosedByClient = new(terminal.fromClient)
			}
		}
		if terminal.err != nil {
			r.flow.Error = flow.NewError(terminal.err.Error())
		}
		r.flow.Resume()
		return nil
	})
}

type received struct {
	fromClient bool
	op         gows.Opcode
	content    []byte
	lengths    []int
	err        error
	injected   bool
	recorded   bool
}

func (r *relay) run(ctx context.Context, c *layer.Context, clock layer.Clock) (received, error) {
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	hookCtx, stopHooks := context.WithCancel(ctx)
	defer stopHooks()
	incoming := make(chan received)
	failures := make(chan received, 2)
	var readers sync.WaitGroup
	prepared := make(chan struct{})
	for _, peer := range []struct {
		conn       *gows.Conn
		fromClient bool
	}{{r.client, true}, {r.server, false}} {
		readers.Go(func() {
			select {
			case <-prepared:
				readMessages(readCtx, peer.conn, peer.fromClient, incoming, failures, stopHooks)
			case <-readCtx.Done():
			}
		})
	}
	interrupted := make(chan struct{})
	abort := func() { _ = r.client.Abort(); _ = r.server.Abort(); close(interrupted) }
	stop := context.AfterFunc(ctx, abort)
	defer func() {
		cancel()
		if stop() {
			abort()
		}
		<-interrupted
		readers.Wait()
	}()
	var flowID string
	snapshot, err := c.Hooks.FireFunc(hookCtx, func(context.Context) error {
		if r.flow.WebSocket == nil {
			r.flow.WebSocket = &wsmodel.Data{}
		}
		flowID = r.flow.ID
		close(prepared)
		return nil
	}, addon.WebSocketStartHook{Flow: r.flow})
	if err != nil {
		select {
		case failure := <-failures:
			return r.fail(ctx, c, clock, failure)
		default:
			return received{}, err
		}
	}
	if snapshot.Killed() {
		return received{}, nil
	}
	inject := c.Inject
	for {
		var event received
		select {
		case <-ctx.Done():
			return received{}, ctx.Err()
		case event = <-failures:
			return r.fail(ctx, c, clock, event)
		case event = <-incoming:
		case injection, ok := <-inject:
			if !ok {
				inject = nil
				continue
			}
			message, ok := injection.Message.(*wsmodel.Message)
			if !ok || message == nil || injection.Flow != r.flow || injection.FlowID != flowID || injection.Direction != layer.DirectionFromClient && injection.Direction != layer.DirectionFromServer {
				continue
			}
			if err := c.Do(ctx, func(context.Context) error {
				event = received{fromClient: injection.Direction == layer.DirectionFromClient, op: gows.Opcode(message.Type), content: slices.Clone(message.Content), injected: true}
				return nil
			}); err != nil {
				return received{}, err
			}
			if event.op == gows.OpcodeText && !utf8.Valid(event.content) {
				event.content = bytes.ToValidUTF8(event.content, []byte("�"))
			}
		}
		dst, compressed := r.server, r.serverCompressed
		if !event.fromClient {
			dst, compressed = r.client, r.clientCompressed
		}
		if event.op.IsControl() {
			if c.Logger != nil {
				peer, control := "server", "pong"
				if event.fromClient {
					peer = "client"
				}
				if event.op == gows.OpcodePing {
					control = "ping"
				}
				c.Logger.Debug(fmt.Sprintf("Received WebSocket %s from %s (payload: %q)", control, peer, event.content))
			}
			if err := dst.WriteFrame(event.op, true, event.content, false); err != nil {
				return event, err
			}
			continue
		}
		snapshot, err := c.Hooks.FireFunc(hookCtx, func(context.Context) error {
			r.flow.WebSocket.Messages = append(r.flow.WebSocket.Messages, &wsmodel.Message{Type: wsmodel.Opcode(event.op), FromClient: event.fromClient, Content: event.content, Injected: event.injected, Timestamp: float64(clock.Now().UnixNano()) / 1e9})
			return nil
		}, addon.WebSocketMessageHook{Flow: r.flow})
		if err != nil {
			select {
			case failure := <-failures:
				return r.fail(ctx, c, clock, failure)
			default:
				return event, err
			}
		}
		if snapshot.Killed() {
			return received{}, nil
		}
		if snapshot.WebSocket == nil || len(snapshot.WebSocket.Messages) == 0 {
			continue
		}
		message := snapshot.WebSocket.Messages[len(snapshot.WebSocket.Messages)-1]
		if message == nil || message.Dropped {
			continue
		}
		if err := writeMessage(dst, event.op, message.Content, event.lengths, compressed); err != nil {
			return event, err
		}
	}
}

func readMessages(ctx context.Context, conn *gows.Conn, fromClient bool, incoming, failures chan<- received, stopHooks context.CancelFunc) {
	var op gows.Opcode
	var content []byte
	var lengths []int
	fail := func(err error) {
		select {
		case failures <- received{fromClient: fromClient, err: err}:
			stopHooks()
		case <-ctx.Done():
		}
	}
	for {
		frame, err := conn.ReadFrame()
		if err != nil {
			fail(err)
			return
		}
		if frame.Header.Opcode.IsControl() {
			event := received{fromClient: fromClient, op: frame.Header.Opcode, content: slices.Clone(frame.Payload)}
			if event.op == gows.OpcodeClose {
				// Terminal events must release an intercepted hook without
				// waiting for the owner to accept another ordinary frame.
				select {
				case failures <- event:
					stopHooks()
				case <-ctx.Done():
				}
				return
			}
			select {
			case incoming <- event:
			case <-ctx.Done():
				return
			}
			continue
		}
		if frame.Header.Opcode.IsData() {
			op = frame.Header.Opcode
		}
		plain, complete, err := conn.DecodeFrame(frame)
		if err != nil {
			fail(err)
			return
		}
		if !frame.Compressed || complete {
			if len(lengths) >= maxFragmentsPerMessage {
				fail(&gows.ProtocolError{Code: gows.CloseMessageTooBig, Reason: "message exceeds fragment limit"})
				return
			}
			lengths = append(lengths, len(plain))
			content = append(content, plain...)
		}
		if complete {
			select {
			case incoming <- received{fromClient: fromClient, op: op, content: content, lengths: lengths}:
			case <-ctx.Done():
				return
			}
			content, lengths = nil, nil
		}
	}
}

func writeMessage(dst *gows.Conn, op gows.Opcode, payload []byte, lengths []int, compressed bool) error {
	if op != gows.OpcodeText && op != gows.OpcodeBinary {
		return fmt.Errorf("websocket: invalid message type %v", op)
	}
	// UTF-8 is a whole-message property: original boundaries may split a
	// code point. Sanitizing each fragment would corrupt unchanged messages.
	if op == gows.OpcodeText && !utf8.Valid(payload) {
		payload = bytes.ToValidUTF8(payload, []byte("�"))
	}
	fragments, err := wsmodel.NewFragmentizer(lengths)
	if err != nil {
		return err
	}
	for content, fin := range fragments.Fragments(payload) {
		err := dst.WriteFrame(op, fin, content, compressed)
		// RFC 7692 permits uncompressed messages even when compression was
		// negotiated. A backend unable to honor this peer's window must not
		// use a larger dictionary or disable the other peer's compression.
		if op.IsData() && errors.Is(err, gows.ErrUnsupportedWindowBits) {
			compressed = false
			err = dst.WriteFrame(op, fin, content, false)
		}
		if err != nil {
			return err
		}
		op = gows.OpcodeContinuation
	}
	return nil
}

func (r *relay) closeBoth(payload []byte) error {
	var clientErr, serverErr error
	var writes sync.WaitGroup
	writes.Go(func() { clientErr = r.client.WriteFrame(gows.OpcodeClose, true, payload, false) })
	writes.Go(func() { serverErr = r.server.WriteFrame(gows.OpcodeClose, true, payload, false) })
	writes.Wait()
	return errors.Join(clientErr, serverErr)
}

func (r *relay) fail(ctx context.Context, c *layer.Context, clock layer.Clock, event received) (received, error) {
	if protocol, ok := errors.AsType[*gows.ProtocolError](event.err); ok {
		reason := []byte(protocol.Reason)
		if len(reason) > 123 {
			reason = reason[:123]
			for !utf8.Valid(reason) {
				reason = reason[:len(reason)-1]
			}
		}
		event.op = gows.OpcodeClose
		event.content = gows.AppendCloseBody(nil, protocol.Code, reason)
	}
	if event.op == gows.OpcodeClose {
		metadataErr := r.recordEnd(ctx, c, clock, event, event.err)
		event.recorded = metadataErr == nil
		return event, errors.Join(event.err, metadataErr, r.closeBoth(event.content))
	}
	return event, event.err
}
