// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"sync"
	"testing"

	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

var configFixtures sync.Map

type configFixtureLayer struct{ *RawQuicLayer }

func (*configFixtureLayer) Kind() hookdata.LayerKind { return "quic-config-test" }

func init() {
	layer.Register("quic-config-test", func(c *layer.Context, _ hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
		value, ok := configFixtures.Load(c.Data.Options)
		if !ok {
			return nil, errors.New("missing test QUIC configuration")
		}
		owner := NewRawQuicLayer(nil)
		owner.modifyConfig = value.(quicConfigModifier)
		return &configFixtureLayer{owner}, nil
	})
}

type closePublicationTrace struct {
	entered       chan struct{}
	release       chan struct{}
	sourceContext chan context.Context
	once          sync.Once
}

func (g *closePublicationTrace) AddProducer() qlogwriter.Recorder { return g }

func (*closePublicationTrace) SupportsSchemas(string) bool { return true }

func (*closePublicationTrace) Close() error { return nil }

func (g *closePublicationTrace) RecordEvent(event qlogwriter.Event) {
	closed, ok := event.(qlog.ConnectionClosed)
	if !ok || closed.Initiator != qlog.InitiatorRemote || closed.ApplicationError == nil {
		return
	}
	// quic-go closes its readers before this callback and cancels Conn.Context
	// afterwards. Hold that publication without delaying the reader's error.
	g.once.Do(func() { close(g.entered) })
	<-g.release
}

func TestQUICWireCloseBeforeContextPublication(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ fromClient bool }{
		"client application close": {fromClient: true},
		"server application close": {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gate := &closePublicationTrace{
				entered:       make(chan struct{}),
				release:       make(chan struct{}),
				sourceContext: make(chan context.Context, 1),
			}
			unblock := sync.OnceFunc(func() { close(gate.release) })
			defer unblock()
			observer := &wireObserver{ended: make(chan *flow.TCPFlow, 1)}
			observer.modifyConfig = func(config *quicgo.Config) {
				config.Tracer = func(ctx context.Context, isClient bool, _ quicgo.ConnectionID) qlogwriter.Trace {
					if isClient == test.fromClient {
						return nil
					}
					gate.sourceContext <- ctx
					return gate
				}
			}
			session := newWireSession(t, nil, observer)
			sender, receiver := session.client, session.origin
			if !test.fromClient {
				sender, receiver = receiver, sender
			}
			if err := sender.CloseWithError(42, "closed"); err != nil {
				t.Fatal(err)
			}
			wireAwait(t, gate.entered)
			sourceContext := wireAwait(t, gate.sourceContext)
			if sourceContext.Err() != nil {
				t.Fatal("proxy source connection context closed before the publication gate")
			}
			wireAwait(t, receiver.Context().Done())
			closed, ok := errors.AsType[*quicgo.ApplicationError](context.Cause(receiver.Context()))
			if !ok || closed.ErrorCode != 42 || closed.ErrorMessage != "closed" {
				t.Fatalf("connection close=%v, want application close 42: closed", context.Cause(receiver.Context()))
			}
			unblock()
		})
	}
}
