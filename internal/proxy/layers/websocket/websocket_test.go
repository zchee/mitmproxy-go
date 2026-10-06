// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/options"
	wsmodel "github.com/zchee/mitmproxy-go/websocket"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(layertest.Timeout):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("operation did not complete:\n%s", buf[:n])
		var zero T
		return zero
	}
}

type observer struct {
	events  []string
	message func(context.Context, *flow.HTTPFlow) error
	start   func(context.Context, *flow.HTTPFlow) error
	started chan *flow.HTTPFlow
}

func (o *observer) WebSocketStart(ctx context.Context, f *flow.HTTPFlow) error {
	o.events = append(o.events, "websocket_start")
	if f.WebSocket == nil || !f.Live {
		return errors.New("start requires a live HTTP flow with WebSocket data")
	}
	if o.start != nil {
		if err := o.start(ctx, f); err != nil {
			return err
		}
	}
	if o.started != nil {
		o.started <- f
	}
	return nil
}

func (o *observer) WebSocketMessage(ctx context.Context, f *flow.HTTPFlow) error {
	o.events = append(o.events, "websocket_message")
	if o.message != nil {
		return o.message(ctx, f)
	}
	return nil
}

func (o *observer) WebSocketEnd(_ context.Context, f *flow.HTTPFlow) error {
	o.events = append(o.events, "websocket_end")
	if f.WebSocket.TimestampEnd == nil {
		return errors.New("end requires terminal metadata")
	}
	return nil
}

type session struct {
	client, server *gows.Conn
	flow           *flow.HTTPFlow
	observed       *observer
	manager        *addon.Manager
	cancel         context.CancelFunc
	done           chan error
	finished       chan struct{}
}

func newSession(t *testing.T, observed *observer, clientCompression, serverCompression bool) *session {
	t.Helper()
	client, clientInput := layertest.Pipe(t)
	server, serverInput := layertest.Pipe(t)
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if observed == nil {
		observed = &observer{}
	}
	if err := manager.Add(t.Context(), observed); err != nil {
		t.Fatal(err)
	}
	f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), connection.NewServer(nil), true)
	cfg := Config{Flow: f, Client: clientInput, Server: serverInput}
	var clientOptions, serverOptions []gows.ConnOption
	if clientCompression {
		cfg.ClientOffer, cfg.ClientResponse = []string{"permessage-deflate"}, []string{"permessage-deflate"}
		clientOptions = append(clientOptions, gows.WithCompressionParams(gows.CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}))
	}
	if serverCompression {
		cfg.ServerOffer, cfg.ServerResponse = []string{"permessage-deflate"}, []string{"permessage-deflate"}
		serverOptions = append(serverOptions, gows.WithCompressionParams(gows.CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}))
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &layer.Context{Hooks: &proxy.HookRunner{Manager: manager}, Do: manager.Do}
	ctx, cancel := context.WithCancel(t.Context())
	s := &session{client: gows.NewClientConn(client, clientOptions...), server: gows.NewServerConn(server, serverOptions...), flow: f, observed: observed, manager: manager, cancel: cancel, done: make(chan error, 1), finished: make(chan struct{})}
	t.Cleanup(func() { cancel(); await(t, s.finished) })
	go func() { s.done <- l.Run(ctx, c); close(s.finished) }()
	return s
}

func readFrame(t *testing.T, c *gows.Conn) gows.Frame {
	t.Helper()
	f, err := c.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	f.Payload = bytes.Clone(f.Payload)
	return f
}

func (s *session) close(t *testing.T, fromClient bool, payload []byte) {
	t.Helper()
	src := s.server
	if fromClient {
		src = s.client
	}
	written := make(chan error, 1)
	go func() { written <- src.WriteFrame(gows.OpcodeClose, true, payload, false) }()
	for _, peer := range []*gows.Conn{s.client, s.server} {
		frame := readFrame(t, peer)
		if frame.Header.Opcode != gows.OpcodeClose || !bytes.Equal(frame.Payload, payload) {
			t.Fatalf("close = %+v, want payload %x", frame, payload)
		}
	}
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	if err := await(t, s.done); err != nil {
		t.Fatal(err)
	}
	if s.flow.Live {
		t.Fatal("completed HTTP flow remains live")
	}
}

func TestNew(t *testing.T) {
	tests := map[string]struct {
		mutate    func(*Config)
		wantError bool
	}{
		"valid":                        {mutate: func(*Config) {}},
		"nil flow":                     {func(c *Config) { c.Flow = nil }, true},
		"nil client":                   {func(c *Config) { c.Client = nil }, true},
		"nil server":                   {func(c *Config) { c.Server = nil }, true},
		"unsolicited client extension": {func(c *Config) { c.ClientResponse = []string{"permessage-deflate"} }, true},
		"unknown server extension":     {func(c *Config) { c.ServerOffer, c.ServerResponse = []string{"x-unknown"}, []string{"x-unknown"} }, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, server := layertest.Pipe(t)
			cfg := Config{Flow: flow.NewHTTPFlow(nil, nil, true), Client: client, Server: server}
			tt.mutate(&cfg)
			l, err := New(cfg)
			if (err != nil) != tt.wantError {
				t.Fatalf("New error = %v, want error %v", err, tt.wantError)
			}
			if err == nil && l.Kind() != "websocket" {
				t.Fatalf("kind = %v", l.Kind())
			}
		})
	}
}

func TestRelayFragmentsAndControls(t *testing.T) {
	s := newSession(t, nil, false, false)
	written := make(chan error, 1)
	go func() {
		for _, f := range []struct {
			op      gows.Opcode
			fin     bool
			payload string
		}{{gows.OpcodeText, false, "foo"}, {gows.OpcodePing, true, "ping"}, {gows.OpcodeContinuation, false, ""}, {gows.OpcodeContinuation, true, "bar"}} {
			if err := s.client.WriteFrame(f.op, f.fin, []byte(f.payload), false); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	ping := readFrame(t, s.server)
	if ping.Header.Opcode != gows.OpcodePing || string(ping.Payload) != "ping" {
		t.Fatalf("ping = %+v", ping)
	}
	for i, want := range []string{"foo", "", "bar"} {
		f := readFrame(t, s.server)
		if string(f.Payload) != want || f.Header.Fin != (i == 2) || !f.Header.Masked {
			t.Fatalf("fragment %d = %+v", i, f)
		}
	}
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	s.close(t, true, gows.AppendCloseBody(nil, gows.CloseNormalClosure, []byte("done")))
	if diff := gocmp.Diff([]string{"websocket_start", "websocket_message", "websocket_end"}, s.observed.events); diff != "" {
		t.Fatal(diff)
	}
	if s.flow.WebSocket.Messages[0].Type != wsmodel.OpText || string(s.flow.WebSocket.Messages[0].Content) != "foobar" {
		t.Fatalf("message = %+v", s.flow.WebSocket.Messages[0])
	}
}

func TestRelayIndependentCompression(t *testing.T) {
	tests := map[string]struct{ client, server bool }{"neither": {}, "client only": {true, false}, "server only": {false, true}, "both": {true, true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, nil, tt.client, tt.server)
			for _, direction := range []bool{true, false} {
				from, to, inputCompressed, outputCompressed := s.client, s.server, tt.client, tt.server
				if !direction {
					from, to, inputCompressed, outputCompressed = s.server, s.client, tt.server, tt.client
				}
				for range 2 {
					payload := bytes.Repeat([]byte("repeated content "), 32)
					written := make(chan error, 1)
					go func() { written <- from.WriteFrame(gows.OpcodeBinary, true, payload, inputCompressed) }()
					frame := readFrame(t, to)
					if frame.Compressed != outputCompressed {
						t.Fatalf("outbound compressed = %v, want %v", frame.Compressed, outputCompressed)
					}
					plain, complete, err := to.DecodeFrame(frame)
					if err != nil || !complete || !bytes.Equal(plain, payload) {
						t.Fatalf("decoded content = %q complete=%v err=%v", plain, complete, err)
					}
					if err := await(t, written); err != nil {
						t.Fatal(err)
					}
				}
			}
			s.close(t, false, nil)
			if s.flow.WebSocket.CloseCode != nil {
				t.Fatalf("absent close code = %v", *s.flow.WebSocket.CloseCode)
			}
			if *s.flow.WebSocket.ClosedByClient {
				t.Fatal("server close attributed to client")
			}
		})
	}
}
