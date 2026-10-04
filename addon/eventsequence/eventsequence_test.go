// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package eventsequence_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/eventsequence"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/state"
	"github.com/zchee/mitmproxy-go/options"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func client() *connection.Client {
	return connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 50000}, connection.Address{Host: "127.0.0.1", Port: 8080}, 1)
}

func server() *connection.Server { return &connection.Server{} }

func httpFlow(t *testing.T, response, ws, failed bool) *flow.HTTPFlow {
	t.Helper()
	f := flow.NewHTTPFlow(client(), server(), false)
	req, err := httpmsg.MakeRequest("GET", "http://example.com/chat", nil, nil)
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}
	f.Request = req
	if response {
		status := 200
		if ws {
			status = 101
		}
		resp, err := httpmsg.MakeResponse(status, nil, nil)
		if err != nil {
			t.Fatalf("MakeResponse: %v", err)
		}
		f.Response = resp
	}
	if ws {
		f.WebSocket = &websocket.Data{Messages: []*websocket.Message{
			websocket.NewMessage(websocket.OpText, true, []byte("hello")),
			websocket.NewMessage(websocket.OpText, false, []byte("hi")),
			websocket.NewMessage(websocket.OpBinary, true, []byte{0, 1}),
		}}
	}
	if failed {
		f.Error = flow.NewError("connection reset")
	}
	return f
}

func tcpFlow(failed bool) *flow.TCPFlow {
	f := flow.NewTCPFlow(client(), server(), false)
	f.Messages = []*tcp.Message{tcp.NewMessage(true, []byte("ping")), tcp.NewMessage(false, []byte("pong"))}
	if failed {
		f.Error = flow.NewError("connection reset")
	}
	return f
}

func udpFlow(failed bool) *flow.UDPFlow {
	f := flow.NewUDPFlow(client(), server(), false)
	f.Messages = []*udp.Message{udp.NewMessage(true, []byte("q")), udp.NewMessage(false, []byte("a"))}
	if failed {
		f.Error = flow.NewError("timeout")
	}
	return f
}

func dnsFlow(response, failed bool) *flow.DNSFlow {
	f := flow.NewDNSFlow(client(), server(), false)
	f.Request = &dns.Message{ID: 1, Query: true}
	if response {
		f.Response = &dns.Message{ID: 1}
	}
	if failed {
		f.Error = flow.NewError("no answer")
	}
	return f
}

func names(seq func(func(addon.Hook) bool)) []string {
	var got []string
	for h := range seq {
		got = append(got, h.Name())
	}
	return got
}

func TestIterate(t *testing.T) {
	tests := map[string]struct {
		flow func(t *testing.T) flow.Flow
		want []string
	}{
		"success: http request and response": {
			flow: func(t *testing.T) flow.Flow { return httpFlow(t, true, false, false) },
			want: []string{"requestheaders", "request", "responseheaders", "response"},
		},
		"success: http websocket takes precedence over error": {
			flow: func(t *testing.T) flow.Flow { return httpFlow(t, true, true, true) },
			want: []string{
				"requestheaders", "request", "responseheaders", "response",
				"websocket_start", "websocket_message", "websocket_message", "websocket_message", "websocket_end",
			},
		},
		"success: http error without response": {
			flow: func(t *testing.T) flow.Flow { return httpFlow(t, false, false, true) },
			want: []string{"requestheaders", "request", "error"},
		},
		"success: http flow without request": {
			flow: func(*testing.T) flow.Flow { return flow.NewHTTPFlow(client(), server(), false) },
		},
		"success: tcp ends": {
			flow: func(*testing.T) flow.Flow { return tcpFlow(false) },
			want: []string{"tcp_start", "tcp_message", "tcp_message", "tcp_end"},
		},
		"success: tcp fails": {
			flow: func(*testing.T) flow.Flow { return tcpFlow(true) },
			want: []string{"tcp_start", "tcp_message", "tcp_message", "tcp_error"},
		},
		"success: udp ends": {
			flow: func(*testing.T) flow.Flow { return udpFlow(false) },
			want: []string{"udp_start", "udp_message", "udp_message", "udp_end"},
		},
		"success: udp fails": {
			flow: func(*testing.T) flow.Flow { return udpFlow(true) },
			want: []string{"udp_start", "udp_message", "udp_message", "udp_error"},
		},
		"success: dns request, response and error": {
			flow: func(*testing.T) flow.Flow { return dnsFlow(true, true) },
			want: []string{"dns_request", "dns_response", "dns_error"},
		},
		"success: dns request only": {
			flow: func(*testing.T) flow.Flow { return dnsFlow(false, false) },
			want: []string{"dns_request"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, names(eventsequence.Iterate(tt.flow(t)))); diff != "" {
				t.Errorf("hooks (-want +got):\n%s", diff)
			}
		})
	}
}

// messages returns the content of the messages a flow holds now.
func messages(f flow.Flow) []string {
	var out []string
	switch f := f.(type) {
	case *flow.HTTPFlow:
		for _, m := range f.WebSocket.Messages {
			out = append(out, string(m.Content))
		}
	case *flow.TCPFlow:
		for _, m := range f.Messages {
			out = append(out, string(m.Content))
		}
	case *flow.UDPFlow:
		for _, m := range f.Messages {
			out = append(out, string(m.Content))
		}
	}
	return out
}

// TestIterateMessages checks that each message hook sees the messages up
// to and including its own, and that a complete iteration restores them.
func TestIterateMessages(t *testing.T) {
	tests := map[string]struct {
		flow func(t *testing.T) flow.Flow
		want [][]string
	}{
		"success: websocket": {
			flow: func(t *testing.T) flow.Flow { return httpFlow(t, true, true, false) },
			want: [][]string{{}, {"hello"}, {"hello", "hi"}, {"hello", "hi", "\x00\x01"}, {"hello", "hi", "\x00\x01"}},
		},
		"success: tcp": {
			flow: func(*testing.T) flow.Flow { return tcpFlow(false) },
			want: [][]string{{}, {"ping"}, {"ping", "pong"}, {"ping", "pong"}},
		},
		"success: udp": {
			flow: func(*testing.T) flow.Flow { return udpFlow(false) },
			want: [][]string{{}, {"q"}, {"q", "a"}, {"q", "a"}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := tt.flow(t)
			before := f.GetState()
			var got [][]string
			for h := range eventsequence.Iterate(f) {
				if strings.HasPrefix(h.Name(), "request") || strings.HasPrefix(h.Name(), "response") {
					continue
				}
				got = append(got, append([]string{}, messages(f)...))
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("messages seen by each hook (-want +got):\n%s", diff)
			}
			if after := f.GetState(); !state.Equal(before, after) {
				t.Errorf("state after a complete iteration differs from the state before:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

func TestIterateStopsEarly(t *testing.T) {
	f := tcpFlow(false)
	for h := range eventsequence.Iterate(f) {
		if h.Name() == "tcp_message" {
			break
		}
	}
	if diff := cmp.Diff([]string{"ping"}, messages(f)); diff != "" {
		t.Errorf("messages after stopping at the first message hook (-want +got):\n%s", diff)
	}
}

// alienFlow is a flow type package flow does not define.
type alienFlow struct{ flow.Flow }

func TestIterateUnknownFlowType(t *testing.T) {
	defer func() {
		r := recover()
		if s, ok := r.(string); !ok || !strings.Contains(s, "Unknown flow type: *eventsequence_test.alienFlow") {
			t.Errorf("recovered %v, want the unknown flow type panic", r)
		}
	}()
	eventsequence.Iterate(&alienFlow{})
	t.Error("Iterate returned for an unknown flow type")
}

// TestAllFlowHooksThroughManager is the hook dispatch acceptance test: an
// addon that implements all 46 hooks receives every event of an HTTP flow
// with WebSocket, a TCP flow, a UDP flow and a DNS flow exactly once, in
// order, each followed by one update with that flow.
func TestAllFlowHooksThroughManager(t *testing.T) {
	r := &addontest.Recorder{}
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{Logger: slog.New(slog.DiscardHandler)})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), r); err != nil {
		t.Fatalf("Add: %v", err)
	}

	flows := []flow.Flow{
		httpFlow(t, true, true, false),
		tcpFlow(false),
		udpFlow(true),
		dnsFlow(true, true),
	}
	for _, f := range flows {
		r.Reset()
		var events []string
		for h := range eventsequence.Iterate(f) {
			events = append(events, h.Name())
			if err := m.Hook(t.Context(), h); err != nil {
				t.Fatalf("Hook(%s): %v", h.Name(), err)
			}
		}

		var want []string
		for _, e := range events {
			want = append(want, e, "update")
		}
		if diff := cmp.Diff(want, r.Hooks()); diff != "" {
			t.Errorf("%s flow: hooks received (-want +got):\n%s", f.Type(), diff)
		}
		for i, c := range r.Calls() {
			got := c.Arg
			if c.Hook == "update" {
				fl, ok := c.Arg.([]flow.Flow)
				if !ok || len(fl) != 1 {
					t.Errorf("%s flow: call %d update got %#v, want one flow", f.Type(), i, c.Arg)
					continue
				}
				got = fl[0]
			}
			if got != any(f) {
				t.Errorf("%s flow: call %d (%s) got %v, want the flow", f.Type(), i, c.Hook, got)
			}
		}
	}
}

// messageWatcher records the newest message each message hook sees.
type messageWatcher struct{ seen []string }

func (w *messageWatcher) WebSocketMessage(_ context.Context, f *flow.HTTPFlow) error {
	w.seen = append(w.seen, string(f.WebSocket.Messages[len(f.WebSocket.Messages)-1].Content))
	return nil
}

func (w *messageWatcher) TCPMessage(_ context.Context, f *flow.TCPFlow) error {
	w.seen = append(w.seen, string(f.Messages[len(f.Messages)-1].Content))
	return nil
}

// TestMessageHooksSeeTheirMessage replays flows through the manager and
// checks that each message handler finds its message last, as on a live
// connection.
func TestMessageHooksSeeTheirMessage(t *testing.T) {
	w := &messageWatcher{}
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{Logger: slog.New(slog.DiscardHandler)})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), w); err != nil {
		t.Fatalf("Add: %v", err)
	}
	for _, f := range []flow.Flow{httpFlow(t, true, true, false), tcpFlow(false)} {
		for h := range eventsequence.Iterate(f) {
			if err := m.Hook(t.Context(), h); err != nil {
				t.Fatalf("Hook: %v", err)
			}
		}
	}
	if diff := cmp.Diff([]string{"hello", "hi", "\x00\x01", "ping", "pong"}, w.seen); diff != "" {
		t.Errorf("messages seen (-want +got):\n%s", diff)
	}
}
