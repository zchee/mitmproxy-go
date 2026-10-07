// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

type deadlineRecorder struct {
	layer.Recorder
	interrupted chan struct{}
}

func (r deadlineRecorder) SetDeadline(t time.Time) error {
	err := r.Recorder.SetDeadline(t)
	r.interrupted <- struct{}{}
	return err
}

func TestCancelAfterReaderEOF(t *testing.T) {
	peer, input := layertest.Pipe(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	interrupted := make(chan struct{}, 1)
	r := deadlineRecorder{Recorder: proxy.Record(input), interrupted: interrupted}
	r.StopRecording()
	o := &owner{ctx: ctx, events: make(chan messageEvent, 2)}
	o.startReader(true, r, nil)
	defer func() {
		cancel()
		o.workers.Wait()
		for _, stop := range o.interrupts {
			stop()
		}
	}()
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if event := await(t, o.events); event.err == nil {
		t.Fatal("reader did not report EOF")
	}
	o.workers.Wait()
	// A response write may still be pending after the peer half-closes.
	cancel()
	await(t, interrupted)
}
