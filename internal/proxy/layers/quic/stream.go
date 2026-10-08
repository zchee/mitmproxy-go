// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
	"github.com/zchee/mitmproxy-go/tcp"
)

// QuicStreamLayer owns the message hooks of one virtual QUIC stream.
// It is created by RawQuicLayer, not by the byte-stream layer registry.
type QuicStreamLayer struct { //nolint:revive // The upstream layer marker is the frozen published name.
	flow           *flow.TCPFlow
	client, server streamSide
	injected       <-chan layer.Injected
	injectionDone  chan<- struct{}
}

type readHalf struct {
	io.Reader
	peek   func([]byte) (int, error)
	cancel func(uint64)
}

type writeHalf struct {
	io.WriteCloser
	cancel func(uint64)
	ctx    context.Context
}

type streamSide struct {
	read  *readHalf
	write *writeHalf
	id    int64
}

// Kind identifies the upstream QuicStreamLayer marker.
func (*QuicStreamLayer) Kind() hookdata.LayerKind { return "quicstream" }

// Run serialises both directions through TCP message hooks and preserves FINs.
// Read and write cancellation affects only this stream, never the QUIC transport.
func (l *QuicStreamLayer) Run(ctx context.Context, c *layer.Context) (result error) {
	if l.flow == nil {
		return errors.New("quic: stream layer requires an admitted stream")
	}
	defer func() {
		endCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), layer.TerminalHookTimeout)
		defer cancel()
		failed := result != nil && ctx.Err() == nil && !errors.Is(result, net.ErrClosed) && !errors.Is(result, io.EOF)
		var hook addon.Hook = addon.TCPEndHook{Flow: l.flow}
		if failed {
			hook = addon.TCPErrorHook{Flow: l.flow}
		}
		_, err := c.Hooks.FireFunc(endCtx, func(context.Context) error {
			if failed {
				l.flow.Error = flow.NewError(result.Error())
			}
			l.flow.ClientConn.State, l.flow.ServerConn.State = connection.Closed, connection.Closed
			l.flow.ClientConn.TimestampEnd, l.flow.ServerConn.TimestampEnd = new(stateutil.Now()), new(stateutil.Now())
			return nil
		}, hook)
		endErr := c.Do(endCtx, func(context.Context) error { l.flow.Live = false; return nil })
		result = errors.Join(result, err, endErr)
	}()
	if _, err := c.Hooks.Fire(ctx, addon.TCPStartHook{Flow: l.flow}); err != nil {
		return err
	}
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type received struct {
		fromClient bool
		content    []byte
		err        error
	}
	incoming := make(chan received)
	ack := [2]chan struct{}{make(chan struct{}, 1), make(chan struct{}, 1)}
	var workers sync.WaitGroup
	remaining := 0
	for _, side := range []struct {
		stream     streamSide
		fromClient bool
	}{{l.client, true}, {l.server, false}} {
		if side.stream.read == nil {
			continue
		}
		remaining++
		workers.Go(func() {
			var buf [64 << 10]byte
			for {
				n, err := side.stream.read.Read(buf[:])
				if n > 0 || err != nil {
					select {
					case incoming <- received{side.fromClient, buf[:n], err}:
					case <-readCtx.Done():
						return
					}
					// The read window stays borrowed until the owner has consumed it.
					select {
					case <-ack[boolIndex(side.fromClient)]:
					case <-readCtx.Done():
						return
					}
				}
				if err != nil {
					return
				}
			}
		})
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(readCtx, func() {
		for _, side := range []streamSide{l.client, l.server} {
			if side.read != nil {
				side.read.cancel(0)
			}
			if side.write != nil {
				side.write.cancel(0)
			}
		}
		close(interrupted)
	})
	defer func() {
		if stop() {
			cancel()
			for _, side := range []streamSide{l.client, l.server} {
				if side.read != nil {
					side.read.cancel(0)
				}
				// Successful FINs must keep retransmitting pending bytes. An
				// abortive CancelWrite here would turn them into RESET_STREAM.
				if side.write != nil && (remaining != 0 || result != nil) {
					side.write.cancel(0)
				}
			}
		} else {
			cancel()
			<-interrupted
		}
		workers.Wait()
	}()
	inject := l.injected
	injectedActive := false
	defer func() {
		if injectedActive {
			notifyInjection(ctx, l.injectionDone)
		}
	}()
	for remaining > 0 {
		var event received
		fromReader := false
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event = <-incoming:
			fromReader = true
		case msg, ok := <-inject:
			if !ok {
				inject = nil
				continue
			}
			m, ok := msg.Message.(*tcp.Message)
			if !ok || m == nil {
				notifyInjection(ctx, l.injectionDone)
				continue
			}
			injectedActive = true
			event = received{fromClient: m.FromClient, content: m.Content}
		}
		dst := l.server
		if !event.fromClient {
			dst = l.client
		}
		if len(event.content) > 0 || event.err == nil {
			snapshot, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
				l.flow.Messages = append(l.flow.Messages, tcp.NewMessage(event.fromClient, slices.Clone(event.content)))
				return nil
			}, addon.TCPMessageHook{Flow: l.flow})
			if err != nil {
				return err
			}
			if snapshot.Killed() {
				return nil
			}
			if snapshot.LastMessage != nil && dst.write != nil {
				content := snapshot.LastMessage.Content
				for len(content) > 0 {
					n, err := dst.write.Write(content)
					if err != nil {
						return err
					}
					if n == 0 {
						return io.ErrNoProgress
					}
					content = content[n:]
				}
			}
		}
		if event.err != nil {
			remaining--
			if dst.write != nil {
				if code, ok := streamResetCode(event.err); ok {
					dst.write.cancel(code)
				} else if errors.Is(event.err, io.EOF) {
					if err := dst.write.Close(); err != nil {
						return err
					}
				} else {
					return event.err
				}
			}
		}
		if fromReader {
			ack[boolIndex(event.fromClient)] <- struct{}{}
		} else {
			notifyInjection(ctx, l.injectionDone)
			injectedActive = false
		}
	}
	return ctx.Err()
}

func notifyInjection(ctx context.Context, done chan<- struct{}) {
	if done == nil {
		return
	}
	select {
	case done <- struct{}{}:
	case <-ctx.Done():
	}
}

func boolIndex(fromClient bool) int {
	if fromClient {
		return 0
	}
	return 1
}
