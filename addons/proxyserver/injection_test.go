// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
	"github.com/zchee/mitmproxy-go/websocket"
)

func TestInjectWebSocket(t *testing.T) {
	tests := map[string]struct {
		strings bool
		isText  *bool
	}{
		"success: native default text":  {},
		"success: native explicit text": {isText: new(true)},
		"success: native binary":        {isText: new(false)},
		"success: string default text":  {strings: true},
		"success: string explicit text": {strings: true, isText: new(true)},
		"success: string binary":        {strings: true, isText: new(false)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			originDone := make(chan error, 1)
			origin := proxytest.StartOrigin(t, func(conn net.Conn) {
				hs, err := gows.Upgrade(conn)
				if err != nil {
					originDone <- err
					return
				}
				server := gows.NewServerConn(conn, gows.WithBuffered(hs.Buffered))
				for {
					op, message, err := server.ReadMessage()
					if err != nil {
						if closed, ok := errors.AsType[*gows.CloseError](err); ok && closed.Code == gows.CloseNormalClosure {
							err = nil
						}
						originDone <- err
						return
					}
					if err := server.WriteMessage(op, message); err != nil {
						originDone <- err
						return
					}
				}
			})
			hooks := &injectionFlows{websocket: make(chan *flow.HTTPFlow, 1), websocketEnded: make(chan struct{}), disconnected: make(chan *connection.Client, 1)}
			p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"mode": []string{"reverse:http://" + origin.Addr}, "rawtcp": false}), proxytest.WithAddons(hooks))
			if err := p.Master.Addons.Add(t.Context(), view.New(p.Master.Addons)); err != nil {
				t.Fatal(err)
			}
			conn, hs, err := gows.Dial(t.Context(), "ws://"+p.Addr+"/inject")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			client := gows.NewClientConn(conn, gows.WithBuffered(hs.Buffered))
			f := awaitInjection(t, hooks.websocket)
			if err := p.Master.Do(t.Context(), func(context.Context) error {
				if !f.Live {
					return errors.New("WebSocket handoff retired its live HTTP flow before injection")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			payload := []byte("injected\nmessage")
			wantOpcode := gows.OpcodeText
			if tt.isText != nil && !*tt.isText {
				payload = []byte("binary\x00\xffmessage")
				wantOpcode = gows.OpcodeBinary
			}
			for _, toClient := range []bool{false, true} {
				if tt.strings {
					message := `injected\nmessage`
					if wantOpcode == gows.OpcodeBinary {
						message = `binary\x00\xffmessage`
					}
					args := []string{"@all", fmt.Sprint(toClient), message}
					if tt.isText != nil {
						args = append(args, fmt.Sprint(*tt.isText))
					}
					if _, err := p.Master.Commands.CallStrings(t.Context(), "inject.websocket", args); err != nil {
						t.Fatal(err)
					}
				} else {
					args := []any{f, toClient, payload}
					if tt.isText != nil {
						args = append(args, *tt.isText)
					}
					if _, err := p.Master.Call(t.Context(), "inject.websocket", args...); err != nil {
						t.Fatal(err)
					}
				}
				op, got, err := client.ReadMessage()
				if err != nil {
					t.Fatal(err)
				}
				if op != wantOpcode {
					t.Fatalf("injected opcode = %v, want %v", op, wantOpcode)
				}
				if diff := gocmp.Diff(payload, got); diff != "" {
					t.Fatalf("injected payload (-want +got):\n%s", diff)
				}
				if err := p.Master.Do(t.Context(), func(context.Context) error {
					var injected []*websocket.Message
					for _, message := range f.WebSocket.Messages {
						if message.Injected {
							injected = append(injected, message)
						}
					}
					wantCount := 1
					if toClient {
						wantCount = 2
					}
					if len(injected) != wantCount {
						t.Fatalf("injected messages = %d, want %d", len(injected), wantCount)
					}
					message := injected[len(injected)-1]
					if message.FromClient != !toClient || message.Type != websocket.Opcode(wantOpcode) || message.Dropped {
						t.Fatalf("injected message metadata = %+v", message)
					}
					if diff := gocmp.Diff(payload, message.Content); diff != "" {
						t.Fatal(diff)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.Master.Call(t.Context(), "inject.websocket", f, true, make([]byte, 128<<10+1)); !errors.Is(err, proxy.ErrInjectionSize) {
				t.Fatalf("oversized WebSocket injection = %v", err)
			}
			if err := client.CloseContext(t.Context(), gows.CloseNormalClosure, ""); err != nil {
				t.Fatal(err)
			}
			if err := awaitInjection(t, originDone); err != nil {
				t.Fatalf("WebSocket origin: %v", err)
			}
			awaitInjection(t, hooks.websocketEnded)
			disconnected := awaitInjection(t, hooks.disconnected)
			if err := p.Master.Do(t.Context(), func(context.Context) error {
				if f.Live || f.WebSocket.TimestampEnd == nil || f.ClientConn != disconnected {
					t.Fatal("injected WebSocket did not finish on its original HTTP flow")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInjectUDP(t *testing.T) {
	tests := map[string]struct {
		strings bool
		payload []byte
	}{
		"success: native binary datagram": {payload: []byte{0, 0xff, '\n', 0}},
		"success: string binary datagram": {strings: true, payload: []byte{0, 0xff, '\n', 0}},
		"success: native empty datagram":  {payload: []byte{}},
		"success: string empty datagram":  {strings: true, payload: []byte{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			origin := proxytest.StartUDPEchoOrigin(t)
			hooks := &injectionFlows{udp: make(chan *flow.UDPFlow, 1)}
			p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"mode": []string{"reverse:udp://" + origin.Addr}}), proxytest.WithAddons(hooks))
			if err := p.Master.Addons.Add(t.Context(), view.New(p.Master.Addons)); err != nil {
				t.Fatal(err)
			}
			client, err := (&net.Dialer{}).DialContext(t.Context(), "udp4", p.Addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write([]byte("ready")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, layer.MaxUDPPacketBytes)
			if n, err := client.Read(buf); err != nil || string(buf[:n]) != "ready" {
				t.Fatalf("UDP warmup = %q, %v", buf[:n], err)
			}
			f := awaitInjection(t, hooks.udp)
			for _, toClient := range []bool{false, true} {
				if tt.strings {
					message := ""
					if len(tt.payload) != 0 {
						message = `\x00\xff\n\x00`
					}
					if _, err := p.Master.Commands.CallStrings(t.Context(), "inject.udp", []string{"@all", fmt.Sprint(toClient), message}); err != nil {
						t.Fatal(err)
					}
				} else if _, err := p.Master.Call(t.Context(), "inject.udp", f, toClient, tt.payload); err != nil {
					t.Fatal(err)
				}
				n, err := client.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(tt.payload, buf[:n]); diff != "" {
					t.Fatalf("injected datagram (-want +got):\n%s", diff)
				}
				if err := p.Master.Do(t.Context(), func(context.Context) error {
					wantCount := 4 // Warmup and server-bound injection each produce an echo.
					if toClient {
						wantCount++
					}
					if len(f.Messages) != wantCount {
						t.Fatalf("UDP messages = %d, want %d", len(f.Messages), wantCount)
					}
					for i, message := range f.Messages[2:] {
						if message.FromClient != (i == 0) {
							t.Fatalf("injected UDP direction = %+v", message)
						}
						if diff := gocmp.Diff(tt.payload, message.Content); diff != "" {
							t.Fatal(diff)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.Master.Call(t.Context(), "inject.udp", f, true, make([]byte, 128<<10+1)); !errors.Is(err, proxy.ErrInjectionSize) {
				t.Fatalf("oversized UDP injection = %v", err)
			}
		})
	}
}

type injectionFlows struct {
	websocket      chan *flow.HTTPFlow
	websocketEnded chan struct{}
	disconnected   chan *connection.Client
	udp            chan *flow.UDPFlow
}

func (h *injectionFlows) WebSocketStart(_ context.Context, f *flow.HTTPFlow) error {
	h.websocket <- f
	return nil
}

func (h *injectionFlows) WebSocketEnd(context.Context, *flow.HTTPFlow) error {
	close(h.websocketEnded)
	return nil
}

func (h *injectionFlows) UDPStart(_ context.Context, f *flow.UDPFlow) error {
	h.udp <- f
	return nil
}

func (h *injectionFlows) ClientDisconnected(_ context.Context, client *connection.Client) error {
	if h.disconnected != nil {
		h.disconnected <- client
	}
	return nil
}

func awaitInjection[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(30 * time.Second):
		stack := make([]byte, 1<<20)
		t.Fatalf("injection peer or hook did not complete\n%s", stack[:runtime.Stack(stack, true)])
		var zero T
		return zero
	}
}
