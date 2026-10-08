// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/flow"
)

// The release occurs beyond the negotiated idle interval to exercise a held
// consumer without relying on machine load or asserting elapsed wall time.
const consumerIdleInterval = 2 * time.Second

const consumerReleaseDelay = 2 * consumerIdleInterval

func TestQUICConsumerAbortAfterIdleInterval(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ idle time.Duration }{
		"success: held consumer retains protocol abort": {idle: consumerIdleInterval},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			consumer := &borrowingConsumer{ready: make(chan bool, 1), release: make(chan struct{}), returned: make(chan struct{}), abort: true}
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 1), consumer: consumer, clientIdleTimeout: tt.idle}
			s := newWireSession(t, nil, o)
			if !wireAwait(t, consumer.ready) || s.client.Context().Err() != nil || s.origin.Context().Err() != nil {
				t.Fatal("consumer received a closed endpoint")
			}
			released := make(chan struct{})
			timer := time.AfterFunc(consumerReleaseDelay, func() {
				close(consumer.release)
				close(released)
			})
			defer func() {
				if !timer.Stop() {
					<-released
				}
			}()
			wireAwait(t, released)
			wireAwait(t, consumer.returned)
			wireAwait(t, s.client.Context().Done())
			cause, ok := errors.AsType[*quicgo.ApplicationError](context.Cause(s.client.Context()))
			if !ok || cause.ErrorCode != 0x102 {
				t.Fatalf("abort=%v, want application close 0x102", context.Cause(s.client.Context()))
			}
			if !s.mode.IsRunning() {
				t.Fatal("per-flow cleanup closed shared listener")
			}
		})
	}
}
