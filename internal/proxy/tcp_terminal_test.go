// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/addontest"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
)

func TestTCPRelayHandlerCancellation(t *testing.T) {
	tests := map[string]struct {
		idle, shutdown bool
	}{
		"idle timeout":      {idle: true},
		"connections close": {},
		"proxy shutdown":    {shutdown: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clock := new(manualClock)
			reading := make(chan struct{})
			_, origin := layertest.Pipe(t)
			bind := &bindAddon{t: t, ids: make(chan string, 1), run: func(ctx context.Context, c *layer.Context) error {
				c.Server = Record(origin)
				c.Client = &oneByteRecorder{Recorder: c.Client, reading: reading}
				selected, err := layer.Build(ctx, c, hookdata.LayerStack{{Kind: hookdata.LayerTCP}})
				if err != nil {
					return err
				}
				return selected.Run(ctx, c)
			}}
			recorder := new(addontest.Recorder)
			runner := newHookRunner(t, recorder, bind, new(terminalInterceptor))
			connections := new(Connections)
			h, err := NewHandler(Config{Manager: runner.Manager, Options: runner.Manager.Options(), Connections: connections})
			if err != nil {
				t.Fatal(err)
			}
			h.clock = clock
			_, client := layertest.Pipe(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- h.Handle(ctx, client, "regular", hookdata.LayerSpec{Kind: topKind}) }()
			await(t, reading)
			switch {
			case test.idle:
				clock.advance(600 * time.Second)
			case test.shutdown:
				cancel()
			default:
				connections.Close()
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			var hooks []string
			for _, name := range recorder.Hooks() {
				if strings.HasPrefix(name, "tcp_") {
					hooks = append(hooks, name)
				}
			}
			if diff := gocmp.Diff([]string{"tcp_start", "tcp_end"}, hooks); diff != "" {
				t.Fatal(diff)
			}
			for _, call := range recorder.Calls() {
				if call.Hook == "tcp_end" {
					f := call.Arg.(*flow.TCPFlow)
					if f.Live || f.Intercepted() {
						t.Error("finished TCP flow remains live or intercepted")
					}
				}
			}
			if connections.Len() != 0 {
				t.Fatal("finished TCP connection was not removed")
			}
		})
	}
}
