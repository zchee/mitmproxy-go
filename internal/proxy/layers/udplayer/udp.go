// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package udplayer relays UDP datagrams through serialised message hooks.
package udplayer

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/udp"
)

func init() {
	layer.Register(hookdata.LayerUDP, func(c *layer.Context, spec hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
		if c.ClientPackets == nil || c.ServerPackets == nil && (c.OpenPackets == nil || c.RecordPackets == nil) {
			return nil, errors.New("udplayer: missing packet transport context")
		}
		l := &udpLayer{}
		if !spec.Ignore {
			l.flow = flow.NewUDPFlow(c.Data.Client, c.Data.Server, true)
			l.flowID = l.flow.ID
		}
		return l, nil
	})
}

type udpLayer struct {
	flow                *flow.UDPFlow
	flowID              string
	terminalHookTimeout time.Duration
}

// Kind identifies this layer as a UDP relay.
func (*udpLayer) Kind() hookdata.LayerKind { return hookdata.LayerUDP }

// Run relays whole datagrams and emits lifecycle hooks for captured flows.
func (l *udpLayer) Run(ctx context.Context, c *layer.Context) (result error) {
	if l.flow != nil {
		defer func() {
			timeout := l.terminalHookTimeout
			if timeout == 0 {
				timeout = layer.TerminalHookTimeout
			}
			endCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
			defer cancel()
			var hook addon.Hook = addon.UDPEndHook{Flow: l.flow}
			failed := result != nil && ctx.Err() == nil && !errors.Is(result, net.ErrClosed) && !errors.Is(result, io.EOF)
			if failed {
				hook = addon.UDPErrorHook{Flow: l.flow}
			}
			_, hookErr := c.Hooks.FireFunc(endCtx, func(context.Context) error {
				if failed {
					l.flow.Error = flow.NewError(result.Error())
				}
				return nil
			}, hook)
			endErr := c.Do(endCtx, func(context.Context) error {
				l.flow.Live = false
				return nil
			})
			result = errors.Join(result, hookErr, endErr)
		}()
		if _, err := c.Hooks.Fire(ctx, addon.UDPStartHook{Flow: l.flow}); err != nil {
			return err
		}
	}
	if c.ServerPackets == nil {
		var metadata *connection.Server
		if err := c.Do(ctx, func(context.Context) error { metadata = c.Data.Server; return nil }); err != nil {
			return err
		}
		opened, actual, err := c.OpenPackets(ctx, metadata)
		if err != nil {
			return err
		}
		c.ServerPackets = c.RecordPackets(opened)
		if err := c.Do(ctx, func(context.Context) error {
			c.Data.Server = actual
			if l.flow != nil {
				l.flow.ServerConn = actual
			}
			return nil
		}); err != nil {
			return err
		}
	}
	c.ServerPackets.StopRecording()
	c.ClientPackets.StopRecording()
	return l.relay(ctx, c)
}

type received struct {
	fromClient bool
	content    []byte
	err        error
}

func (l *udpLayer) relay(ctx context.Context, c *layer.Context) error {
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	incoming := make(chan received)
	var readers sync.WaitGroup
	readers.Go(func() { readPackets(readCtx, c.ClientPackets, true, incoming) })
	readers.Go(func() { readPackets(readCtx, c.ServerPackets, false, incoming) })

	// The handler owns both transports. Interrupt and join readers without
	// closing either tuple or their shared listener, including blocked writes.
	interrupted := make(chan struct{})
	interrupt := func() {
		_ = c.ClientPackets.SetDeadline(time.Now())
		_ = c.ServerPackets.SetDeadline(time.Now())
		close(interrupted)
	}
	stop := context.AfterFunc(readCtx, interrupt)
	defer func() {
		cancel()
		if stop() {
			interrupt()
		}
		<-interrupted
		readers.Wait()
		_ = c.ClientPackets.SetDeadline(time.Time{})
		_ = c.ServerPackets.SetDeadline(time.Time{})
	}()

	inject := c.Inject
	if l.flow == nil {
		inject = nil
	}
	for {
		var event received
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event = <-incoming:
		case injected, ok := <-inject:
			if !ok {
				inject = nil
				continue
			}
			message, ok := injected.Message.(*udp.Message)
			if !ok || message == nil || injected.FlowID != l.flowID {
				continue
			}
			event = received{fromClient: injected.Direction == layer.DirectionFromClient, content: message.Content}
		}
		if event.err != nil {
			return event.err
		}
		dst := c.ServerPackets
		if !event.fromClient {
			dst = c.ClientPackets
		}
		content := event.content
		if l.flow != nil {
			snapshot, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
				l.flow.Messages = append(l.flow.Messages, udp.NewMessage(event.fromClient, event.content))
				return nil
			}, addon.UDPMessageHook{Flow: l.flow})
			if err != nil {
				return err
			}
			if snapshot.Killed() {
				return nil
			}
			content = nil
			if snapshot.LastUDPMessage != nil {
				content = snapshot.LastUDPMessage.Content
			}
		}
		if len(content) > layer.MaxUDPPacketBytes {
			return layer.ErrPacketOverflow
		}
		// Empty payloads are datagrams too. A short write must never be retried
		// as another datagram, which would change the sender's packet boundaries.
		n, err := dst.WriteTo(content, nil)
		if err != nil {
			return err
		}
		if n != len(content) {
			return io.ErrShortWrite
		}
	}
}

func readPackets(ctx context.Context, conn layer.PacketTransport, fromClient bool, incoming chan<- received) {
	var window [layer.MaxUDPPacketBytes + 1]byte
	for {
		n, _, err := conn.ReadFrom(window[:])
		if n > layer.MaxUDPPacketBytes {
			n, err = 0, layer.ErrPacketOverflow
		}
		select {
		case incoming <- received{fromClient: fromClient, content: slices.Clone(window[:n]), err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil || ctx.Err() != nil {
			return
		}
	}
}
