// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package tcplayer relays TCP streams through serialised message hooks.
package tcplayer

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
)

func init() {
	layer.Register(hookdata.LayerTCP, func(c *layer.Context, spec hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
		l := &tcpLayer{}
		if !spec.Ignore {
			l.flow = flow.NewTCPFlow(c.Data.Client, c.Data.Server, true)
		}
		return l, nil
	})
}

// tcpLayer relays a raw TCP connection. A nil flow is the ignore mode:
// bytes are forwarded as they arrive, without a flow and without hooks.
type tcpLayer struct {
	flow *flow.TCPFlow
}

// Kind identifies this layer as a TCP relay.
func (*tcpLayer) Kind() hookdata.LayerKind { return hookdata.LayerTCP }

// Run relays both TCP directions and emits lifecycle hooks for captured flows.
func (l *tcpLayer) Run(ctx context.Context, c *layer.Context) error {
	if l.flow != nil {
		if _, err := c.Hooks.Fire(ctx, addon.TCPStartHook{Flow: l.flow}); err != nil {
			return err
		}
	}
	if c.Server == nil {
		var metadata *connection.Server
		if err := c.Do(ctx, func(context.Context) error {
			metadata = c.Data.Server
			return nil
		}); err != nil {
			return err
		}
		opened, actual, err := c.Pool.Open(ctx, metadata, layer.OpenOptions{})
		if err != nil {
			if l.flow == nil {
				return err
			}
			_, hookErr := c.Hooks.FireFunc(ctx, func(context.Context) error {
				l.flow.Error = flow.NewError(err.Error())
				return nil
			}, addon.TCPErrorHook{Flow: l.flow})
			return errors.Join(err, hookErr)
		}
		c.Server = c.Record(opened)
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
	c.Server.StopRecording()
	c.Client.StopRecording()
	err := l.relay(ctx, c, c.Server)
	if l.flow == nil {
		return err
	}
	_, hookErr := c.Hooks.Fire(ctx, addon.TCPEndHook{Flow: l.flow})
	endErr := c.Do(context.WithoutCancel(ctx), func(context.Context) error {
		l.flow.Live = false
		return nil
	})
	return errors.Join(err, hookErr, endErr)
}

type received struct {
	fromClient bool
	content    []byte
	err        error
}

func (l *tcpLayer) relay(ctx context.Context, c *layer.Context, server layer.Conn) error {
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	incoming := make(chan received)
	var readers sync.WaitGroup
	readers.Go(func() { readChunks(readCtx, c.Client, true, incoming) })
	readers.Go(func() { readChunks(readCtx, server, false, incoming) })

	// The handler owns both transports. Deadlines interrupt I/O without closing
	// them, including a write blocked while the connection is cancelled.
	interrupted := make(chan struct{})
	interrupt := func() {
		_ = c.Client.SetDeadline(time.Now())
		_ = server.SetDeadline(time.Now())
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
		_ = c.Client.SetDeadline(time.Time{})
		_ = server.SetDeadline(time.Time{})
	}()

	inject := c.Inject
	if l.flow == nil {
		// Without a flow there is nothing an addon could inject into.
		inject = nil
	}
	for remaining := 2; remaining > 0; {
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
			message, ok := injected.Message.(*tcp.Message)
			if !ok || message == nil || injected.Flow != l.flow {
				continue
			}
			if err := c.Do(ctx, func(context.Context) error {
				event = received{fromClient: message.FromClient, content: slices.Clone(message.Content)}
				return nil
			}); err != nil {
				return err
			}
		}
		dst := server
		if !event.fromClient {
			dst = c.Client
		}
		content := event.content
		// Unlike socket reads, an injected message may have empty content.
		if l.flow != nil && (len(event.content) > 0 || event.err == nil) {
			snapshot, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
				l.flow.Messages = append(l.flow.Messages, tcp.NewMessage(event.fromClient, event.content))
				return nil
			}, addon.TCPMessageHook{Flow: l.flow})
			if err != nil {
				return err
			}
			if snapshot.Killed() {
				return nil
			}
			content = nil
			if snapshot.LastMessage != nil {
				content = snapshot.LastMessage.Content
			}
		}
		for len(content) > 0 {
			n, err := dst.Write(content)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrNoProgress
			}
			content = content[n:]
		}
		if event.err != nil {
			remaining--
			if err := dst.CloseWrite(); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func readChunks(ctx context.Context, conn layer.Conn, fromClient bool, incoming chan<- received) {
	var buf [64 << 10]byte
	for {
		// Copy only the received bytes: retained messages must neither alias the
		// next Read nor keep an entire read window alive for a short message.
		n, err := conn.Read(buf[:])
		if n > 0 || err != nil {
			select {
			case incoming <- received{fromClient: fromClient, content: slices.Clone(buf[:n]), err: err}:
			case <-ctx.Done():
				return
			}
		}
		if err != nil || ctx.Err() != nil {
			return
		}
	}
}
