// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"sync"
	"testing"

	quicgo "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

var consumerFixtures sync.Map

type consumerFixtureLayer struct{ *RawQuicLayer }

func (*consumerFixtureLayer) Kind() hookdata.LayerKind { return "quic-consumer-test" }

func init() {
	layer.Register("quic-consumer-test", func(c *layer.Context, _ hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
		value, ok := consumerFixtures.Load(c.Data.Options)
		if !ok {
			return nil, errors.New("missing test consumer")
		}
		return &consumerFixtureLayer{NewRawQuicLayer(value.(ConnectionConsumer))}, nil
	})
}

func (o *wireObserver) NextLayer(_ context.Context, d *hookdata.NextLayer) error {
	if o.modifyConfig != nil {
		d.Layer = hookdata.LayerStack{{Kind: "quic-config-test"}}
	} else if o.consumer != nil {
		d.Layer = hookdata.LayerStack{{Kind: "quic-consumer-test"}}
	}
	return nil
}

type borrowingConsumer struct {
	ready    chan bool
	release  chan struct{}
	returned chan struct{}
	abort    bool
}

func (b *borrowingConsumer) RunQUIC(ctx context.Context, _ *layer.Context, client, server *quicgo.Conn) error {
	defer close(b.returned)
	b.ready <- client.Context().Err() == nil && server.Context().Err() == nil
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	if b.abort {
		err := errors.New("consumer protocol abort")
		_ = client.CloseWithError(0x102, err.Error())
		return err
	}
	return nil
}

func TestQUICConsumerBorrowing(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ abort bool }{"normal return": {}, "protocol abort": {abort: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			consumer := &borrowingConsumer{ready: make(chan bool, 1), release: make(chan struct{}), returned: make(chan struct{}), abort: tt.abort}
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 1), consumer: consumer}
			s := newWireSession(t, nil, o)
			if !wireAwait(t, consumer.ready) {
				t.Fatal("consumer received a closed endpoint")
			}
			if s.client.Context().Err() != nil || s.origin.Context().Err() != nil {
				t.Fatal("owner closed a borrowed endpoint before return")
			}
			close(consumer.release)
			wireAwait(t, consumer.returned)
			<-s.client.Context().Done()
			if tt.abort {
				cause, ok := errors.AsType[*quicgo.ApplicationError](context.Cause(s.client.Context()))
				if !ok || cause.ErrorCode != 0x102 {
					t.Fatalf("abort=%v", context.Cause(s.client.Context()))
				}
			}
			if !s.mode.IsRunning() {
				t.Fatal("per-flow cleanup closed shared listener")
			}
		})
	}
}
