// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// TestHandlerPipeTwoLayerReplay drives a fake two-layer stack over net.Pipe
// peers with an injected clock: the top layer reads one byte per Read, the
// selected child must still receive every recorded byte exactly once at
// handover, and the idle clock never advances past its deadline meanwhile.
func TestHandlerPipeTwoLayerReplay(t *testing.T) {
	const greeting = "greeting"
	clock := &manualClock{current: time.Unix(0, 0)}
	echoed := make(chan []byte, 1)
	bind := &bindAddon{
		t:   t,
		ids: make(chan string, 1),
		run: func(ctx context.Context, c *layer.Context) error {
			c.Client = &oneByteRecorder{Recorder: c.Client, reading: make(chan struct{})}
			child, err := layer.Next(ctx, c)
			if err != nil {
				return err
			}
			return child.Run(ctx, c)
		},
		child: func(_ context.Context, c *layer.Context) error {
			// Read through EOF, not just the expected prefix: a second replay
			// appended after the correct bytes must fail the assertion too.
			data, err := io.ReadAll(c.Client)
			echoed <- data
			return err
		},
	}
	runner := newHookRunner(t, bind, &selectorAddon{next: func(_ context.Context, data *hookdata.NextLayer) error {
		if len(data.DataClient) == len(greeting) {
			data.Layer = hookdata.LayerStack{{Kind: childKind}}
		}
		return nil
	}})
	h, err := NewHandler(Config{
		Manager:     runner.Manager,
		Options:     runner.Manager.Options(),
		Connections: &Connections{},
		Dialer:      (&poolDialer{t: t}).dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.clock = clock
	ours, theirs := net.Pipe()
	t.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
	done := make(chan error, 1)
	go func() { done <- h.Handle(t.Context(), theirs, "regular", hookdata.LayerSpec{Kind: topKind}) }()
	written := make(chan error, 1)
	go func() {
		for _, b := range []byte(greeting) {
			if _, err := ours.Write([]byte{b}); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	if err := ours.Close(); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]byte(greeting), await(t, echoed)); diff != "" {
		t.Fatalf("bytes seen by the child (-want +got):\n%s", diff)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}
