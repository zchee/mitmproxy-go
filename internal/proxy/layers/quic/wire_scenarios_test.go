// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	quicgo "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
)

func (o *wireObserver) ClientConnected(_ context.Context, c *connection.Client) error {
	if o.connectionID == "" {
		o.connectionID = c.ID
	}
	return nil
}

func (o *wireObserver) ClientDisconnected(_ context.Context, c *connection.Client) error {
	if o.disconnected != nil && c.ID == o.connectionID {
		o.disconnected <- struct{}{}
	}
	return nil
}

func (o *wireObserver) UDPStart(_ context.Context, f *flow.UDPFlow) error {
	if o.udpStarted != nil {
		o.udpStarted <- f
	}
	return nil
}

func (*wireObserver) UDPMessage(_ context.Context, f *flow.UDPFlow) error {
	m := f.Messages[len(f.Messages)-1]
	m.Content = bytes.ToUpper(m.Content)
	return nil
}

func TestQUICWireVerification(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	// py:test/mitmproxy/addons/test_tlsconfig.py QUIC verify_ok/insecure rows
	// are exercised on real certificates here, not only configuration values.
	tests := map[string]struct {
		settings        map[string]any
		wrongName, fail bool
		want            []string
	}{
		"trusted IP":                         {settings: map[string]any{"keep_host_header": false}},
		"lazy handshake order":               {settings: map[string]any{"connection_strategy": "lazy"}, want: []string{"hello", "start-client", "established-client", "start-server", "established-server"}},
		"explicit TLS 1.3 cipher names":      {settings: map[string]any{"ciphers_client": new("TLS_CHACHA20_POLY1305_SHA256"), "ciphers_server": new("TLS_CHACHA20_POLY1305_SHA256")}},
		"ssl_insecure permits name mismatch": {settings: map[string]any{"ssl_insecure": true}, wrongName: true},
		"name mismatch rejected":             {wrongName: true, fail: true},
		"untrusted CA rejected":              {settings: map[string]any{"ssl_verify_upstream_trusted_ca": (*string)(nil)}, fail: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &wireObserver{ended: make(chan *flow.TCPFlow, 1), expectOriginFailure: tt.fail, failed: make(chan struct{}, 1)}
			if tt.wrongName {
				o.hello = func(d *hookdata.ClientHello) { d.Context.Server.SNI = new("wrong-name.example") }
			}
			s := newWireSession(t, tt.settings, o)
			if !tt.fail {
				wireAwaitServerEstablished(t, o)
			}
			if err := s.manager.Do(t.Context(), func(context.Context) error {
				want := tt.want
				if want == nil {
					want = []string{"hello", "start-server", "established-server", "start-client", "established-client"}
				}
				if tt.fail {
					want = []string{"hello", "start-server", "failed-server", "start-client", "established-client"}
				}
				// A failed origin can close the client before its handshake completes.
				if tt.fail && len(o.events) == 4 {
					want = want[:4]
				}
				if diff := gocmp.Diff(want, o.events); diff != "" {
					t.Error(diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQUICWireDatagrams(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	o := &wireObserver{ended: make(chan *flow.TCPFlow, 1), udpStarted: make(chan *flow.UDPFlow, 1)}
	s := newWireSession(t, nil, o)
	f := wireAwait(t, o.udpStarted)
	for _, source := range []struct {
		from, to *quicgo.Conn
		payload  string
	}{{s.client, s.origin, "client packet"}, {s.origin, s.client, "server packet"}} {
		if err := source.from.SendDatagram([]byte(source.payload)); err != nil {
			t.Fatal(err)
		}
		got, err := source.to.ReceiveDatagram(s.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff(bytes.ToUpper([]byte(source.payload)), got); diff != "" {
			t.Fatal(diff)
		}
	}
	if err := s.handler.Inject(s.ctx, layer.Injected{Flow: f, Message: udp.NewMessage(true, []byte("injected"))}); err != nil {
		t.Fatal(err)
	}
	got, err := s.origin.ReceiveDatagram(s.ctx)
	if err != nil || string(got) != "INJECTED" {
		t.Fatalf("datagram injection=%q,%v", got, err)
	}
}

func TestQUICWireInjectionAndStopSending(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	o := &wireObserver{ended: make(chan *flow.TCPFlow, 1), started: make(chan *flow.TCPFlow, 1)}
	s := newWireSession(t, nil, o)
	stream, err := s.client.OpenStreamSync(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	peer, err := s.origin.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	f := wireAwait(t, o.started)
	if err := s.handler.Inject(s.ctx, layer.Injected{Flow: f, Message: tcp.NewMessage(false, []byte("injected"))}); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, 8)
	if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != "INJECTED" {
		t.Fatalf("stream injection=%q,%v", buf, err)
	}
	peer.CancelRead(123)
	<-stream.Context().Done()
	reset, ok := errors.AsType[*quicgo.StreamError](context.Cause(stream.Context()))
	if !ok || reset.ErrorCode != 123 {
		t.Fatalf("STOP_SENDING=%v", context.Cause(stream.Context()))
	}
	_ = peer.Close()
	_, _ = io.ReadAll(stream)
	wireAwait(t, o.ended)
}

func TestQUICWirePausedStreamIsolation(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	paused, release := make(chan struct{}), make(chan struct{})
	o := &wireObserver{ended: make(chan *flow.TCPFlow, 2), message: func(ctx context.Context, f *flow.TCPFlow) error {
		m := f.Messages[len(f.Messages)-1]
		if string(m.Content) == "pause" {
			close(paused)
			_, err := addon.Concurrent(ctx, func(ctx context.Context) error {
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			return err
		}
		return nil
	}}
	s := newWireSession(t, nil, o)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	first, err := s.client.OpenStreamSync(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("warm")); err != nil {
		t.Fatal(err)
	}
	firstPeer, err := s.origin.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	warm := make([]byte, 4)
	if _, err := io.ReadFull(firstPeer, warm); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("pause")); err != nil {
		t.Fatal(err)
	}
	wireAwait(t, paused)
	second, err := s.client.OpenStreamSync(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("sibling")); err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	peer, err := s.origin.AcceptStream(s.ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "sibling" {
		t.Fatalf("sibling=%q,%v", got, err)
	}
	_ = peer.Close()
	_, _ = io.ReadAll(second)
	wireAwait(t, o.ended)
	close(release)
	_ = first.Close()
	got, err = io.ReadAll(firstPeer)
	if err != nil || string(got) != "pause" {
		t.Fatalf("resumed=%q,%v", got, err)
	}
	_ = firstPeer.Close()
	_, _ = io.ReadAll(first)
	wireAwait(t, o.ended)
}
