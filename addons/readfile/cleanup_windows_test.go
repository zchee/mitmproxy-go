// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package readfile

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
)

type windowsReadPipe struct {
	*gatedClosePipe
	reading chan struct{}
	once    sync.Once
}

func (p *windowsReadPipe) Read(buf []byte) (int, error) {
	p.once.Do(func() { close(p.reading) })
	return p.File.Read(buf)
}

func TestWindowsDonePendingPipeOwnership(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = output.Close() })
	pipe := &windowsReadPipe{
		gatedClosePipe: &gatedClosePipe{File: input, entered: make(chan struct{}), release: make(chan struct{}), loaded: make(chan struct{})},
		reading:        make(chan struct{}),
	}
	m, r, logs := newReader(t, pipe)
	release := sync.OnceFunc(func() { close(pipe.release) })
	t.Cleanup(release)
	if err := configure(t, m, map[string]any{"rfile": new("-")}); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	wait(t, pipe.reading)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stopped := make(chan struct{})
	var stopErr error
	go func() {
		stopErr = m.Do(ctx, r.Done)
		close(stopped)
	}()
	wait(t, pipe.entered)
	cancel()
	wait(t, stopped)
	if !errors.Is(stopErr, context.Canceled) {
		t.Errorf("Done = %v, want context canceled", stopErr)
	}
	var cleanup *loaderCleanup
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		cleanup = r.cleanup
		if err := r.Running(ctx); err == nil || !strings.Contains(err.Error(), "cleanup is still pending") {
			t.Errorf("Running while Close is pending = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cleanup.finished:
		t.Error("canceled wait discarded the pending pipe cleanup")
	default:
	}
	// EOF releases the native read before the fixture allows Close to finish.
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	release()
	wait(t, cleanup.finished)
	wait(t, r.done)
	if logs.Len() != 0 {
		t.Errorf("cancelled pipe logged corruption: %s", logs.String())
	}
}
