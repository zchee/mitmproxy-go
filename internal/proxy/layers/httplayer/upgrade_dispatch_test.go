// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
)

type upgradeObserver struct {
	lifecycle []string
	content   map[bool]string
	started   chan *flow.TCPFlow
}

func (a *upgradeObserver) TCPStart(_ context.Context, f *flow.TCPFlow) error {
	a.lifecycle = append(a.lifecycle, "tcp_start")
	a.content = make(map[bool]string)
	if a.started != nil {
		a.started <- f
	}
	return nil
}

func (a *upgradeObserver) TCPMessage(_ context.Context, f *flow.TCPFlow) error {
	message := f.Messages[len(f.Messages)-1]
	a.content[message.FromClient] += string(message.Content)
	return nil
}

func (a *upgradeObserver) TCPEnd(_ context.Context, _ *flow.TCPFlow) error {
	a.lifecycle = append(a.lifecycle, "tcp_end")
	return nil
}

func TestLayerUpgradeDispatch(t *testing.T) {
	tests := map[string]struct {
		protocol string
		rawTCP   bool
	}{
		"success: custom protocol relays through TCP hooks":  {protocol: "custom", rawTCP: true},
		"success: disabled raw TCP closes after response":    {protocol: "custom"},
		"success: WebSocket uses TCP until its layer exists": {protocol: "websocket", rawTCP: true},
		"success: WebSocket without raw TCP closes":          {protocol: "websocket"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var httpFlow *flow.HTTPFlow
			a := &streamAddon{edit: func(_ string, f *flow.HTTPFlow) { httpFlow = f }}
			raw := "rawtcp=false"
			if tt.rawTCP {
				raw = "rawtcp=true"
			}
			s := newLayerSession(t, a, "connection_strategy=lazy", "websocket=true", raw)
			observer := &upgradeObserver{started: make(chan *flow.TCPFlow, 1)}
			if err := s.m.Do(t.Context(), func(ctx context.Context) error { return s.m.Addons.Add(ctx, observer) }); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			s.c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			inject := make(chan layer.Injected, 1)
			s.c.Inject = inject
			s.start(hookdata.HTTPModeRegular)
			head := "Connection: Upgrade\r\nUpgrade: " + tt.protocol + "\r\n\r\n"
			write(t, s.client, "GET http://origin.test/ HTTP/1.1\r\n"+head+"client greeting")
			origin := await(t, s.pool.origins)
			expectRead(t, origin, "GET / HTTP/1.1\r\n"+head)
			response := "HTTP/1.1 101 Switching Protocols\r\n" + head
			write(t, origin, response+"server greeting")
			expectRead(t, s.client, response)
			if tt.rawTCP {
				expectRead(t, s.client, "server greeting")
				expectRead(t, origin, "client greeting")
				f := await(t, observer.started)
				inject <- layer.Injected{Flow: f, Message: tcp.NewMessage(true, []byte("injected request"))}
				expectRead(t, origin, "injected request")
				inject <- layer.Injected{Flow: f, Message: tcp.NewMessage(false, []byte("injected response"))}
				expectRead(t, s.client, "injected response")
				if err := s.client.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := origin.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			if data, err := io.ReadAll(s.client); err != nil || len(data) != 0 {
				t.Fatalf("after upgrade: (%q, %v), want EOF without extra bytes", data, err)
			}
			if err := await(t, s.done); err != nil {
				t.Fatal(err)
			}
			if httpFlow.WebSocket != nil {
				t.Fatal("TCP upgrade unexpectedly set HTTP WebSocket metadata")
			}
			if tt.rawTCP {
				if diff := gocmp.Diff([]string{"tcp_start", "tcp_end"}, observer.lifecycle); diff != "" {
					t.Fatalf("TCP lifecycle (-want +got):\n%s", diff)
				}
				if diff := gocmp.Diff(map[bool]string{true: "client greetinginjected request", false: "server greetinginjected response"}, observer.content); diff != "" {
					t.Fatalf("TCP messages (-want +got):\n%s", diff)
				}
				if logs.Len() != 0 {
					t.Fatalf("unexpected upgrade warning: %s", &logs)
				}
			} else {
				if len(observer.lifecycle) != 0 {
					t.Fatalf("disabled upgrade fired TCP hooks: %v", observer.lifecycle)
				}
				const warning = `level=WARN msg="Sent HTTP 101 response, but no protocol is enabled to upgrade to."`
				if !strings.Contains(logs.String(), warning) {
					t.Fatalf("logs = %q, want %q", logs.String(), warning)
				}
			}
		})
	}
}
