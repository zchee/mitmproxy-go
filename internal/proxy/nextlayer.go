// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type sniffRead struct {
	side int
	data []byte
	err  error
}

// nextLayer retains input independently of hook arguments: handlers may edit
// their view, and a read completed during a hook must still replay at handover.
func nextLayer(ctx context.Context, c *layer.Context) (layer.Layer, error) {
	if c == nil || c.Data == nil || c.Client == nil || c.Hooks == nil || c.Do == nil {
		return nil, errors.New("proxy: next layer requires client, metadata, hooks and dispatch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// A previous selector or protocol parser may already have stopped the
	// recorder. Rewrap it so every selection has its own bounded replay.
	c.Client.StopRecording()
	c.Client = Record(c.Client)
	inputs := []layer.Recorder{c.Client}
	if c.Server != nil {
		c.Server.StopRecording()
		c.Server = Record(c.Server)
		inputs = append(inputs, c.Server)
	}
	readCtx, cancel := context.WithCancel(ctx)
	reads := make(chan sniffRead)
	var readers sync.WaitGroup
	for side, input := range inputs {
		readers.Go(func() { readSniff(readCtx, input, side, reads) })
	}
	interrupted := make(chan struct{})
	context.AfterFunc(readCtx, func() {
		for _, input := range inputs {
			_ = input.SetReadDeadline(time.Now())
		}
		close(interrupted)
	})
	finish := sync.OnceFunc(func() {
		cancel()
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
		case <-ctx.Done():
			return nil, ctx.Err()
		case read := <-reads:
			if len(read.data) != 0 {
				received[read.side] = append(received[read.side], read.data...)
				_, err := c.Hooks.FireFunc(ctx, func(context.Context) error {
					data.DataClient = bytes.Clone(received[0])
					data.DataServer = bytes.Clone(received[1])
					return nil
				}, addon.NextLayerHook{Data: data})
				if err != nil {
					return nil, err
				}
				var stack hookdata.LayerStack
				if err := c.Do(ctx, func(context.Context) error {
					stack = slices.Clone(data.Layer)
					return nil
				}); err != nil {
					return nil, err
				}
				if stack != nil {
					// Constructors and children must never race a sniff reader,
					// including one reading the other side's greeting.
					finish()
					for _, spec := range stack {
						switch spec.Kind {
						case hookdata.LayerRegular, hookdata.LayerReverse, hookdata.LayerUpstream:
							return nil, fmt.Errorf("proxy: next layer cannot select top-level mode %q", spec.Kind)
						}
					}
					return layer.Build(ctx, c, stack)
				}
			}
			if read.err != nil && (read.side == 0 || !errors.Is(read.err, io.EOF)) {
				return nil, read.err
			}
		}
	}
}

func readSniff(ctx context.Context, input layer.Recorder, side int, reads chan<- sniffRead) {
	var window [4096]byte
	for empty := 0; ctx.Err() == nil; {
		n, err := input.Read(window[:])
		if n == 0 && err == nil {
			empty++
			if empty < 100 {
				continue
			}
			err = io.ErrNoProgress
		} else {
			empty = 0
		}
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
