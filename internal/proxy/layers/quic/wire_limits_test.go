// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	quicgo "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/flow"
)

func TestQUICWireEarlierSettings(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ preserve bool }{"default interception leaf": {}, "earlier settings retained": {preserve: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 1), preserveSettings: tt.preserve}
			s := newWireSession(t, nil, o)
			if tt.preserve {
				if diff := gocmp.Diff(o.clientSettings.Certificate.Raw, s.client.ConnectionState().TLS.PeerCertificates[0].Raw); diff != "" {
					t.Fatal(diff)
				}
				if err := s.manager.Do(s.ctx, func(context.Context) error {
					if o.clientTLS.Settings != o.clientSettings {
						t.Error("default addon replaced earlier settings pointer")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestQUICWireConnectionClose(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ fromClient bool }{"client application close": {fromClient: true}, "server application close": {}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 1)}
			s := newWireSession(t, nil, o)
			sender, receiver := s.client, s.origin
			if !tt.fromClient {
				sender, receiver = receiver, sender
			}
			if err := sender.CloseWithError(42, "closed"); err != nil {
				t.Fatal(err)
			}
			<-receiver.Context().Done()
			closed, ok := errors.AsType[*quicgo.ApplicationError](context.Cause(receiver.Context()))
			if !ok || closed.ErrorCode != 42 || closed.ErrorMessage != "closed" {
				t.Fatalf("connection close=%v", context.Cause(receiver.Context()))
			}
		})
	}
}

func TestQUICWireStreamAdmission(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{ count int }{"one active stream": {count: 1}, "one hundred active streams": {count: 100}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 101)}
			s := newWireSession(t, nil, o)
			clients := make([]*quicgo.Stream, 0, tt.count)
			origins := make([]*quicgo.Stream, 0, tt.count)
			for range tt.count {
				stream, err := s.client.OpenStreamSync(s.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				peer, err := s.origin.AcceptStream(s.ctx)
				if err != nil {
					t.Fatal(err)
				}
				var data [1]byte
				if _, err := io.ReadFull(peer, data[:]); err != nil || data[0] != 'X' {
					t.Fatalf("admission data=%q,%v", data, err)
				}
				clients = append(clients, stream)
				origins = append(origins, peer)
			}
			if tt.count == 100 {
				if stream, err := s.client.OpenStream(); err == nil {
					stream.CancelRead(0)
					stream.CancelWrite(0)
					t.Fatal("accepted beyond incoming stream limit")
				}
			}
			if err := clients[0].Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(origins[0]); err != nil {
				t.Fatal(err)
			}
			if err := origins[0].Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(clients[0]); err != nil {
				t.Fatal(err)
			}
			wireAwait(t, o.ended)
			stream, err := s.client.OpenStreamSync(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write([]byte("next")); err != nil {
				t.Fatal(err)
			}
			peer, err := s.origin.AcceptStream(s.ctx)
			if err != nil {
				t.Fatal(err)
			}
			var data [4]byte
			if _, err := io.ReadFull(peer, data[:]); err != nil || string(data[:]) != "NEXT" {
				t.Fatalf("replacement stream=%q,%v", data, err)
			}
		})
	}
}

// Upstream raw-layer scenario map (test__raw_layers.py):
// TestQuicStreamLayer.test_force_raw and test_simple: TestQUICWireStreams.
// TestRawQuicLayer.test_force_raw: wire stream/datagram/reset/connection-close rows.
// test_error: TestQUICWireVerification origin failures.
// test_msg_inject: TestQUICWireDatagrams and TestQUICWireInjectionAndStopSending.
// test_reset_with_end_hook: TestQUICWireReset.
// test_close_with_end_hooks: wire terminal hooks and consumer/fixture cleanup.
// test_full_close: TestQUICWireInjectionAndStopSending and consumer abort.
// test_invalid_stream_event, test_invalid_event, test_invalid_connection_command:
// not applicable; the Go layer has no untyped event/command dispatch API.
// test_open_connection's arbitrary per-stream child protocol is not exercised by
// the frozen raw-relay constructor; HTTP/3 endpoint consumption is tested separately.
