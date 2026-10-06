// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

type packetHeadTimeout struct{}

// Error identifies expiration of the DTLS protocol-head read deadline.
func (packetHeadTimeout) Error() string { return "proxy: DTLS protocol head read timed out" }

// Timeout classifies the expired protocol-head deadline as a network timeout.
func (packetHeadTimeout) Timeout() bool { return true }

// Temporary reports that protocol selection cannot retry after its deadline expires.
func (packetHeadTimeout) Temporary() bool { return false }

func nextPacketLayer(ctx context.Context, c *layer.Context) (layer.Layer, error) {
	if c.Data == nil || c.Hooks == nil || c.Do == nil {
		return nil, errors.New("proxy: next packet layer requires metadata, hooks and dispatch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.ClientPackets.StopRecording()
	c.ClientPackets = RecordPackets(c.ClientPackets)
	inputs := []layer.PacketRecorder{c.ClientPackets}
	if c.ServerPackets != nil {
		c.ServerPackets.StopRecording()
		c.ServerPackets = RecordPackets(c.ServerPackets)
		inputs = append(inputs, c.ServerPackets)
	}
	readCtx, cancel := context.WithCancelCause(ctx)
	clock := c.Clock
	if clock == nil {
		clock = layer.WallClock
	}
	var stopHead func() bool
	defer func() {
		if stopHead != nil {
			stopHead()
		}
	}()
	reads := make(chan sniffRead)
	var readers sync.WaitGroup
	for side, input := range inputs {
		readers.Go(func() { readPacketSniff(readCtx, input, side, reads) })
	}
	interrupted := make(chan struct{})
	context.AfterFunc(readCtx, func() {
		for _, input := range inputs {
			_ = input.SetReadDeadline(time.Now())
		}
		close(interrupted)
	})
	finish := sync.OnceFunc(func() {
		cancel(context.Canceled)
		<-interrupted
		readers.Wait()
		for _, input := range inputs {
			_ = input.SetReadDeadline(time.Time{})
			input.StopRecording()
		}
	})
	defer finish()
	var received [2][]byte
	data := &hookdata.NextLayer{Context: c.Data}
	for {
		select {
		case <-readCtx.Done():
			return nil, context.Cause(readCtx)
		case read := <-reads:
			if readCtx.Err() != nil {
				return nil, context.Cause(readCtx)
			}
			if read.err == nil || len(read.data) != 0 {
				if len(received[read.side])+len(read.data) > layer.PacketQueueBytes {
					return nil, layer.ErrPacketOverflow
				}
				received[read.side] = append(received[read.side], read.data...)
				if stopHead == nil && tlsparse.StartsLikeDTLSRecord(received[0]) {
					stopHead = clock.AfterFunc(layer.HeadReadTimeout, func() { cancel(packetHeadTimeout{}) })
				}
				_, err := c.Hooks.FireFunc(readCtx, func(context.Context) error {
					data.DataClient = slices.Clip(received[0])
					data.DataServer = slices.Clip(received[1])
					return nil
				}, addon.NextLayerHook{Data: data})
				if readCtx.Err() != nil {
					return nil, context.Cause(readCtx)
				}
				if err != nil {
					return nil, err
				}
				var stack hookdata.LayerStack
				if err := c.Do(readCtx, func(context.Context) error { stack = slices.Clone(data.Layer); return nil }); err != nil {
					if readCtx.Err() != nil {
						return nil, context.Cause(readCtx)
					}
					return nil, err
				}
				if readCtx.Err() != nil {
					return nil, context.Cause(readCtx)
				}
				if stack != nil {
					if stopHead != nil && !stopHead() {
						return nil, packetHeadTimeout{}
					}
					finish()
					for _, spec := range stack {
						switch spec.Kind {
						case hookdata.LayerRegular, hookdata.LayerReverse, hookdata.LayerUpstream:
							return nil, fmt.Errorf("proxy: next packet layer cannot select top-level mode %q", spec.Kind)
						}
					}
					return layer.Build(ctx, c, stack)
				}
			}
			if read.err != nil {
				return nil, read.err
			}
		}
	}
}

func readPacketSniff(ctx context.Context, input layer.PacketRecorder, side int, reads chan<- sniffRead) {
	window := make([]byte, layer.MaxUDPPacketBytes)
	for ctx.Err() == nil {
		n, _, err := input.ReadFrom(window)
		select {
		case reads <- sniffRead{side: side, data: bytes.Clone(window[:n]), err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}
