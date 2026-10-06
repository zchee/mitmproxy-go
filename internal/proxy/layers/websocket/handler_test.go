// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"context"
	"errors"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/options"
	wsmodel "github.com/zchee/mitmproxy-go/websocket"
)

const (
	handlerTestKind     hookdata.LayerKind = "websocket-owner-test"
	handlerSnapshotKind hookdata.LayerKind = "websocket-snapshot-test"
)

func init() {
	for _, kind := range []hookdata.LayerKind{handlerTestKind, handlerSnapshotKind} {
		layer.Register(kind, func(c *layer.Context, _ hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
			c.Data.Server.Address = new(connection.Address{Host: "echo.test", Port: 80})
			return &handlerTestLayer{flow: flow.NewHTTPFlow(c.Data.Client, c.Data.Server, true), server: c.Data.Server, kind: kind}, nil
		})
	}
}

type handlerTestLayer struct {
	flow   *flow.HTTPFlow
	server *connection.Server
	kind   hookdata.LayerKind
}

func (l *handlerTestLayer) Kind() hookdata.LayerKind { return l.kind }

func (l *handlerTestLayer) Run(ctx context.Context, c *layer.Context) error {
	conn, metadata, err := c.Pool.Open(ctx, l.server, layer.OpenOptions{})
	if err != nil {
		return err
	}
	c.Server = c.Record(conn)
	c.Server.StopRecording()
	c.Client.StopRecording()
	child, err := New(Config{Flow: l.flow, Client: c.Client, Server: c.Server})
	if err != nil {
		return err
	}
	if err := c.Do(ctx, func(context.Context) error {
		c.Data.Server, l.flow.ServerConn = metadata, metadata
		c.Data.Layers = append(c.Data.Layers, child)
		return nil
	}); err != nil {
		return err
	}
	if l.kind == handlerSnapshotKind {
		c.Hooks = &mutateAfterSnapshotHooks{Hooks: c.Hooks, do: c.Do}
	}
	return child.Run(ctx, c)
}

type handlerSession struct {
	*session
	handler                          *proxy.Handler
	clientTransport, serverTransport layer.Conn
}

func newHandlerSession(t *testing.T, observed *observer, kinds ...hookdata.LayerKind) *handlerSession {
	t.Helper()
	client, clientInput := layertest.Pipe(t)
	server, serverInput := layertest.Pipe(t)
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if observed == nil {
		observed = &observer{}
	}
	observed.started = make(chan *flow.HTTPFlow, 1)
	if err := manager.Add(t.Context(), observed); err != nil {
		t.Fatal(err)
	}
	h, err := proxy.NewHandler(proxy.Config{Manager: manager, Options: manager.Options(), Connections: &proxy.Connections{}, Dialer: func(context.Context, *connection.Server) (layer.Conn, error) { return serverInput, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	s := &handlerSession{session: &session{client: gows.NewClientConn(client), server: gows.NewServerConn(server), observed: observed, manager: manager, cancel: cancel, done: make(chan error, 1), finished: make(chan struct{})}, handler: h, clientTransport: client, serverTransport: server}
	t.Cleanup(func() { cancel(); await(t, s.finished) })
	kind := handlerTestKind
	if len(kinds) > 0 {
		kind = kinds[0]
	}
	go func() {
		s.done <- h.Handle(ctx, clientInput, "regular", hookdata.LayerSpec{Kind: kind})
		close(s.finished)
	}()
	s.flow = await(t, observed.started)
	return s
}

func TestHandlerInjection(t *testing.T) {
	tests := map[string]struct {
		fromClient bool
		content    []byte
	}{
		"client text": {true, []byte("hello")},
		"server text": {false, []byte("world")},
		"empty":       {true, nil},
		"rechunked":   {true, bytes.Repeat([]byte("x"), 8001)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newHandlerSession(t, nil)
			message := &wsmodel.Message{Type: wsmodel.OpText, FromClient: tt.fromClient, Content: bytes.Clone(tt.content), Timestamp: -1}
			if err := s.handler.Inject(t.Context(), layer.Injected{Flow: s.flow, Message: message}); err != nil {
				t.Fatal(err)
			}
			message.Content = []byte("caller changed the message")
			to := s.client
			if tt.fromClient {
				to = s.server
			}
			var content []byte
			var sizes []int
			for {
				f := readFrame(t, to)
				content = append(content, f.Payload...)
				sizes = append(sizes, len(f.Payload))
				if f.Header.Fin {
					break
				}
			}
			if !bytes.Equal(content, tt.content) {
				t.Fatalf("injection content = %q, want %q", content, tt.content)
			}
			if len(tt.content) == 8001 {
				if diff := gocmp.Diff([]int{4000, 4000, 1}, sizes); diff != "" {
					t.Fatal(diff)
				}
			}
			s.close(t, true, nil)
			if len(s.flow.WebSocket.Messages) != 1 {
				t.Fatalf("message count = %d", len(s.flow.WebSocket.Messages))
			}
			got := s.flow.WebSocket.Messages[0]
			if !got.Injected || got.FromClient != tt.fromClient || got.Timestamp <= 0 || got == message {
				t.Fatalf("recorded injection = %+v", got)
			}
		})
	}
}

func TestHandlerInjectionFullAndValidation(t *testing.T) {
	s := newHandlerSession(t, &observer{start: func(_ context.Context, f *flow.HTTPFlow) error { f.Intercept(); return nil }})
	tests := map[string]struct {
		injected layer.Injected
		want     error
	}{
		"wrong flow identity": {layer.Injected{Flow: s.flow, FlowID: "another-flow", Message: &wsmodel.Message{Type: wsmodel.OpText}}, proxy.ErrInjectionIdentity},
		"wrong type":          {layer.Injected{Flow: s.flow, Message: "not a message"}, proxy.ErrInjectionType},
		"wrong direction":     {layer.Injected{Flow: s.flow, Direction: layer.DirectionFromClient, Message: &wsmodel.Message{Type: wsmodel.OpText}}, proxy.ErrInjectionDirection},
		"too large":           {layer.Injected{Flow: s.flow, Message: &wsmodel.Message{Type: wsmodel.OpBinary, Content: make([]byte, layer.MaxInjectionBytes+1)}}, proxy.ErrInjectionSize},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := s.handler.Inject(t.Context(), tt.injected); !errors.Is(err, tt.want) {
				t.Fatalf("Inject = %v, want %v", err, tt.want)
			}
		})
	}
	for range layer.InjectionCapacity {
		if err := s.handler.Inject(t.Context(), layer.Injected{Flow: s.flow, Message: &wsmodel.Message{Type: wsmodel.OpBinary}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.handler.Inject(t.Context(), layer.Injected{Flow: s.flow, Message: &wsmodel.Message{Type: wsmodel.OpBinary}}); !errors.Is(err, proxy.ErrInjectionFull) {
		t.Fatalf("full queue = %v", err)
	}
	if err := s.manager.Do(t.Context(), func(context.Context) error { s.flow.Resume(); return nil }); err != nil {
		t.Fatal(err)
	}
	for range layer.InjectionCapacity {
		if f := readFrame(t, s.client); len(f.Payload) != 0 || f.Header.Opcode != gows.OpcodeBinary || !f.Header.Fin {
			t.Fatalf("empty injected frame = %+v", f)
		}
	}
	s.close(t, true, nil)
	if err := s.handler.Inject(t.Context(), layer.Injected{Flow: s.flow, Message: &wsmodel.Message{Type: wsmodel.OpBinary}}); !errors.Is(err, proxy.ErrInjectionClosed) {
		t.Fatalf("closed flow accepted injection: %v", err)
	}
}
