// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
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
	unexpected    chan string
	once          sync.Once
}

func (g *closePublicationTrace) AddProducer() qlogwriter.Recorder { return g }

func (*closePublicationTrace) SupportsSchemas(string) bool { return true }

func (*closePublicationTrace) Close() error { return nil }

func (g *closePublicationTrace) RecordEvent(event qlogwriter.Event) {
	closed, ok := event.(qlog.ConnectionClosed)
	if !ok {
		return
	}
	if closed.Initiator != qlog.InitiatorRemote || closed.ApplicationError == nil {
		application, transport := "none", "none"
		if closed.ApplicationError != nil {
			application = fmt.Sprintf("%#x", uint64(*closed.ApplicationError))
		}
		if closed.ConnectionError != nil {
			transport = fmt.Sprintf("%#x", uint64(*closed.ConnectionError))
		}
		diagnostic := fmt.Sprintf("initiator=%v application=%s transport=%s trigger=%v reason=%q", closed.Initiator, application, transport, closed.Trigger, closed.Reason[:min(len(closed.Reason), 256)])
		select {
		case g.unexpected <- diagnostic:
		default:
		}
		return
	}
	// quic-go closes its readers before this callback and cancels Conn.Context
	// afterwards. Hold that publication without delaying the reader's error.
	g.once.Do(func() { close(g.entered) })
	<-g.release
}

func TestQUICClosePublicationUnexpected(t *testing.T) {
	tests := map[string]struct {
		event qlog.ConnectionClosed
		want  string
	}{
		"local application close": {
			event: qlog.ConnectionClosed{Initiator: qlog.InitiatorLocal, ApplicationError: new(qlog.ApplicationErrorCode(42)), Reason: strings.Repeat("r", 1024)},
			want:  "application=0x2a transport=none",
		},
		"remote transport close": {
			event: qlog.ConnectionClosed{Initiator: qlog.InitiatorRemote, ConnectionError: new(qlog.TransportErrorCode(7)), Reason: strings.Repeat("r", 1024)},
			want:  "application=none transport=0x7",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gate := &closePublicationTrace{entered: make(chan struct{}), unexpected: make(chan string, 1)}
			gate.RecordEvent(test.event)
			gate.RecordEvent(qlog.ConnectionClosed{Initiator: qlog.InitiatorLocal, Reason: "later close"})
			if diff := gocmp.Diff(1, len(gate.unexpected)); diff != "" {
				t.Fatalf("retained close count (-want +got):\n%s", diff)
			}
			diagnostic := <-gate.unexpected
			want := fmt.Sprintf("initiator=%v %s trigger=%v reason=%q", test.event.Initiator, test.want, test.event.Trigger, strings.Repeat("r", 256))
			if diff := gocmp.Diff(want, diagnostic); diff != "" {
				t.Fatalf("first bounded close diagnostic (-want +got):\n%s", diff)
			}
			select {
			case <-gate.entered:
				t.Fatal("unexpected close opened the strict application-close gate")
			default:
			}
		})
	}
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
				unexpected:    make(chan string, 1),
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
			sourceContext := wireAwait(t, gate.sourceContext)
			wireAwaitServerEstablished(t, observer)
			// Listener acceptance does not acknowledge raw relay application progress.
			for _, path := range [][2]*quicgo.Conn{{session.client, session.origin}, {session.origin, session.client}} {
				if err := path[0].SendDatagram([]byte("READY")); err != nil {
					t.Fatal(err)
				}
				data, err := path[1].ReceiveDatagram(session.ctx)
				if err != nil {
					t.Fatalf("QUIC relay readiness failed: %v; source cause=%v", err, context.Cause(sourceContext))
				}
				if diff := gocmp.Diff([]byte("READY"), data); diff != "" {
					t.Fatalf("readiness datagram (-want +got):\n%s", diff)
				}
			}
			sender, receiver := session.client, session.origin
			if !test.fromClient {
				sender, receiver = receiver, sender
			}
			if err := sender.CloseWithError(42, "closed"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-gate.entered:
			case diagnostic := <-gate.unexpected:
				t.Fatalf("unexpected QUIC close before publication gate: %s; source cause=%v", diagnostic, context.Cause(sourceContext))
			case <-sourceContext.Done():
				cause := context.Cause(sourceContext)
				select {
				case diagnostic := <-gate.unexpected:
					t.Fatalf("QUIC source closed before publication gate: %T: %v; %s", cause, cause, diagnostic)
				default:
					t.Fatalf("QUIC source closed before publication gate: %T: %v", cause, cause)
				}
			case <-time.After(wireWaitTimeout):
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				t.Fatalf("QUIC close publication gate did not complete: source cause=%v; fixture cause=%v\n%s", context.Cause(sourceContext), context.Cause(session.ctx), buf[:n])
			}
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
