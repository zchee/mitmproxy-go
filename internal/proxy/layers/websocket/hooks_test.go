// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"bytes"
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	wsmodel "github.com/zchee/mitmproxy-go/websocket"
)

func TestHandlerModifyAndDrop(t *testing.T) {
	tests := map[string]struct {
		edit  []byte
		sizes []int
		drop  bool
	}{
		"same length":      {[]byte("foobaz"), []int{3, 3}, false},
		"different length": {bytes.Repeat([]byte("x"), 8001), []int{4000, 4000, 1}, false},
		"empty edit":       {nil, []int{0}, false},
		"drop":             {nil, []int{4}, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newHandlerSession(t, &observer{message: func(_ context.Context, f *flow.HTTPFlow) error {
				if len(f.WebSocket.Messages) != 1 {
					return nil
				}
				m := f.WebSocket.Messages[0]
				if tt.drop {
					m.Drop()
				} else {
					m.Content = bytes.Clone(tt.edit)
				}
				return nil
			}})
			written := make(chan error, 1)
			go func() {
				if err := s.client.WriteFrame(gows.OpcodeText, false, []byte("foo"), false); err != nil {
					written <- err
					return
				}
				if err := s.client.WriteFrame(gows.OpcodeContinuation, true, []byte("bar"), false); err != nil {
					written <- err
					return
				}
				if tt.drop {
					written <- s.client.WriteFrame(gows.OpcodeText, true, []byte("keep"), false)
				} else {
					written <- nil
				}
			}()
			var sizes []int
			var payload []byte
			for {
				f := readFrame(t, s.server)
				sizes = append(sizes, len(f.Payload))
				payload = append(payload, f.Payload...)
				if f.Header.Fin {
					break
				}
			}
			want := tt.edit
			if tt.drop {
				want = []byte("keep")
			}
			if !bytes.Equal(payload, want) {
				t.Fatalf("payload = %q, want %q", payload, want)
			}
			if diff := gocmp.Diff(tt.sizes, sizes); diff != "" {
				t.Fatal(diff)
			}
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
			s.close(t, true, nil)
			if s.flow.WebSocket.Messages[0].Dropped != tt.drop {
				t.Fatal("drop state was not recorded")
			}
		})
	}
}

func TestHandlerKill(t *testing.T) {
	tests := map[string]struct{ start bool }{"start": {true}, "message": {}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			o := &observer{}
			kill := func(_ context.Context, f *flow.HTTPFlow) error { return f.Kill() }
			if tt.start {
				o.start = kill
			} else {
				o.message = kill
			}
			s := newHandlerSession(t, o)
			if !tt.start {
				if err := s.client.WriteFrame(gows.OpcodeBinary, true, []byte("not forwarded"), false); err != nil {
					t.Fatal(err)
				}
			}
			_ = await(t, s.done)
			if _, err := s.server.ReadFrame(); err == nil {
				t.Fatal("killed flow forwarded data")
			}
			if s.flow.Error == nil || s.flow.Error.Msg != flow.KilledMessage || s.flow.Live {
				t.Fatalf("killed flow: error=%v live=%v", s.flow.Error, s.flow.Live)
			}
			if s.observed.events[len(s.observed.events)-1] != "websocket_end" {
				t.Fatalf("events=%v", s.observed.events)
			}
		})
	}
}

func TestHandlerInterceptSerializesBothDirectionsAndInjection(t *testing.T) {
	entered := make(chan struct{}, 1)
	s := newHandlerSession(t, &observer{message: func(_ context.Context, f *flow.HTTPFlow) error {
		if len(f.WebSocket.Messages) == 1 {
			f.Intercept()
			entered <- struct{}{}
		}
		return nil
	}})
	if err := s.client.WriteFrame(gows.OpcodeText, true, []byte("original"), false); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	if err := s.handler.Inject(t.Context(), layer.Injected{Flow: s.flow, Message: &wsmodel.Message{Type: wsmodel.OpText, FromClient: true, Content: []byte("injected")}}); err != nil {
		t.Fatal(err)
	}
	if err := s.server.WriteFrame(gows.OpcodeText, true, []byte("reply"), false); err != nil {
		t.Fatal(err)
	}
	if err := s.manager.Do(t.Context(), func(context.Context) error {
		if len(s.flow.WebSocket.Messages) != 1 {
			t.Errorf("another message bypassed the intercepted owner: %d", len(s.flow.WebSocket.Messages))
		}
		m := s.flow.WebSocket.Messages[0]
		m.Content, m.Type, m.FromClient = []byte("edited"), wsmodel.OpBinary, false
		s.flow.Resume()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"edited", "injected"} {
		f := readFrame(t, s.server)
		if f.Header.Opcode != gows.OpcodeText || string(f.Payload) != want {
			t.Fatalf("server frame = %+v, want original TEXT type and %q", f, want)
		}
	}
	if f := readFrame(t, s.client); string(f.Payload) != "reply" {
		t.Fatalf("client reply = %+v", f)
	}
	s.close(t, false, nil)
	if len(s.flow.WebSocket.Messages) != 3 {
		t.Fatalf("message count=%d, want received, injected, reply", len(s.flow.WebSocket.Messages))
	}
}

func TestHandlerDisconnectDuringInterception(t *testing.T) {
	tests := map[string]struct{ start bool }{"start": {true}, "message": {}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			o := &observer{}
			intercept := func(_ context.Context, f *flow.HTTPFlow) error { f.Intercept(); entered <- struct{}{}; return nil }
			if tt.start {
				o.start = intercept
			} else {
				o.message = intercept
			}
			s := newHandlerSession(t, o)
			if !tt.start {
				if err := s.client.WriteFrame(gows.OpcodeBinary, true, []byte("intercepted"), false); err != nil {
					t.Fatal(err)
				}
			}
			await(t, entered)
			if err := s.clientTransport.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = await(t, s.done)
			if s.flow.Error == nil || s.flow.Live || s.flow.WebSocket.CloseCode == nil || *s.flow.WebSocket.CloseCode != 1006 {
				t.Fatalf("abnormal terminal metadata: error=%v live=%v websocket=%+v", s.flow.Error, s.flow.Live, s.flow.WebSocket)
			}
			if !*s.flow.WebSocket.ClosedByClient {
				t.Fatal("client EOF attributed to server")
			}
			if s.observed.events[len(s.observed.events)-1] != "websocket_end" {
				t.Fatalf("events=%v", s.observed.events)
			}
		})
	}
}

func TestHandlerCloseDuringInterception(t *testing.T) {
	entered := make(chan struct{}, 1)
	s := newHandlerSession(t, &observer{message: func(_ context.Context, f *flow.HTTPFlow) error { f.Intercept(); entered <- struct{}{}; return nil }})
	if err := s.client.WriteFrame(gows.OpcodeText, true, []byte("intercepted"), false); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	s.close(t, true, gows.AppendCloseBody(nil, gows.CloseNormalClosure, []byte("done")))
	if s.flow.Error != nil {
		t.Fatalf("normal close recorded error: %v", s.flow.Error)
	}
}
