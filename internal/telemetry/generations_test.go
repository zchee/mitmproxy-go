// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/websocket"
)

func wireAttributes(t *testing.T, input []*commonpb.KeyValue) map[string]any {
	t.Helper()
	values := make(map[string]any, len(input))
	for _, item := range input {
		switch value := item.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			values[item.Key] = value.StringValue
		case *commonpb.AnyValue_IntValue:
			values[item.Key] = value.IntValue
		case *commonpb.AnyValue_DoubleValue:
			values[item.Key] = value.DoubleValue
		case *commonpb.AnyValue_BoolValue:
			values[item.Key] = value.BoolValue
		default:
			t.Fatalf("non-scalar exported attribute %s: %T", item.Key, value)
		}
	}
	return values
}

func beginActive(t *testing.T, x *liveFixture, kind string) flow.Flow {
	t.Helper()
	switch kind {
	case "http", "websocket":
		f := httpFlow(t)
		if kind == "websocket" {
			f.Response.StatusCode = 101
			f.Response.Headers.Set("Upgrade", "websocket")
			f.WebSocket = &websocket.Data{TimestampEnd: new(105.25)}
		}
		liveHook(t, x, addon.RequestHook{Flow: f})
		if kind == "websocket" {
			liveHook(t, x, addon.ResponseHook{Flow: f})
			liveHook(t, x, addon.WebSocketStartHook{Flow: f})
		}
		return f
	case "tcp":
		client, server := clientAndServer()
		f := flow.NewTCPFlow(client, server, true)
		liveHook(t, x, addon.TCPStartHook{Flow: f})
		changeFlow(t, x.m, func() { f.Messages = append(f.Messages, tcp.NewMessage(true, []byte("req"))) })
		liveHook(t, x, addon.TCPMessageHook{Flow: f})
		return f
	default:
		t.Fatalf("unsupported active-flow kind %q", kind)
		return nil
	}
}

func endActive(t *testing.T, x *liveFixture, f flow.Flow, kind string) {
	t.Helper()
	switch kind {
	case "http":
		liveHook(t, x, addon.ResponseHook{Flow: f.(*flow.HTTPFlow)})
	case "websocket":
		liveHook(t, x, addon.WebSocketEndHook{Flow: f.(*flow.HTTPFlow)})
	case "tcp":
		value := f.(*flow.TCPFlow)
		changeFlow(t, x.m, func() { value.Messages = append(value.Messages, tcp.NewMessage(false, []byte("reply"))) })
		liveHook(t, x, addon.TCPMessageHook{Flow: value})
		liveHook(t, x, addon.TCPEndHook{Flow: value})
	}
}

func assertWireSpan(t *testing.T, span *tracepb.Span, kind string) {
	t.Helper()
	if span.Name != "proxy.flow."+kind {
		t.Fatalf("wire span name=%q", span.Name)
	}
	if diff := gocmp.Diff(expectedAttributes(kind), wireAttributes(t, span.Attributes)); diff != "" {
		t.Fatalf("complete wire attributes (-want +got):\n%s", diff)
	}
	end := uint64(time.Unix(102, 750000000).UnixNano())
	if kind == "websocket" {
		end = uint64(time.Unix(105, 250000000).UnixNano())
	}
	if span.StartTimeUnixNano != uint64(time.Unix(100, 250000000).UnixNano()) || span.EndTimeUnixNano != end {
		t.Fatalf("wire lifecycle timestamps=%d..%d", span.StartTimeUnixNano, span.EndTimeUnixNano)
	}
}

func waitPublished(t *testing.T, x *liveFixture, endpoint string) {
	t.Helper()
	for {
		g := currentGeneration(x)
		if g != nil && g.endpoint == endpoint {
			return
		}
		awaitSignal(t, x.dispatchEnded)
	}
}

func fillStalledQueue(t *testing.T, x *liveFixture, collector *stalledCollector, fill bool) []*flow.HTTPFlow {
	t.Helper()
	var flows []*flow.HTTPFlow
	for range 128 {
		f := httpFlow(t)
		flows = append(flows, f)
		liveHook(t, x, addon.ResponseHook{Flow: f})
	}
	awaitSignal(t, collector.started)
	if fill {
		for range 1024 {
			f := httpFlow(t)
			flows = append(flows, f)
			liveHook(t, x, addon.ResponseHook{Flow: f})
		}
	}
	return flows
}

func closeWhileReplacing(t *testing.T, fill bool) {
	t.Helper()
	a, b := newStalledCollector(t), newOwnedCollector(t, false)
	x := liveController(t, Config{Version: "test"}, nil)
	setEndpoint(t, x, a.server.URL)
	retained := fillStalledQueue(t, x, a, fill)
	active := beginActive(t, x, "http")
	old := currentGeneration(x)
	if err := x.m.Do(t.Context(), func(ctx context.Context) error {
		return x.m.Options.Update(ctx, map[string]any{endpointOption: b.server.URL})
	}); err != nil {
		t.Fatal(err)
	}
	waitPublished(t, x, b.server.URL)
	current := currentGeneration(x)
	started := time.Now()
	if err := x.c.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 10*time.Second {
		t.Fatal("Close exceeded the single total budget")
	}
	assertJoined(t, old)
	assertJoined(t, current)
	a.joined(t)
	spans := b.spans()
	if len(spans) != 1 || spans[0].Status.GetCode() != 2 || spans[0].StartTimeUnixNano != uint64(time.Unix(100, 250000000).UnixNano()) {
		t.Fatalf("current provider did not finalize exactly one active flow: %v", spans)
	}
	if x.c.Status().ActiveFlows != 0 {
		t.Fatal("Close left active scalar flows")
	}
	select {
	case <-x.c.done:
	default:
		t.Fatal("reconfigure worker not joined")
	}
	runtime.KeepAlive(active)
	runtime.KeepAlive(retained)
}

func TestTelemetryGenerations(t *testing.T) {
	tests := map[string]struct {
		kind          string
		viaEmpty      bool
		repeated      bool
		disableEnable bool
		closeDuring   bool
	}{
		"active_http_switch":       {kind: "http"},
		"active_websocket_switch":  {kind: "websocket"},
		"active_tcp_switch":        {kind: "tcp"},
		"switch_via_empty":         {kind: "http", viaEmpty: true},
		"close_during_reconfigure": {closeDuring: true},
		"repeated_switches":        {kind: "http", repeated: true},
		"disable_enable":           {kind: "http", disableEnable: true},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				if tt.closeDuring {
					closeWhileReplacing(t, false)
					return
				}
				a, b := newOwnedCollector(t, false), newOwnedCollector(t, false)
				x := liveController(t, Config{Version: "test"}, nil)
				setEndpoint(t, x, a.server.URL)
				active := beginActive(t, x, tt.kind)
				if x.c.Status().ActiveFlows != 1 {
					t.Fatal("active gauge did not open")
				}
				if err := flushLive(t, x); err != nil {
					t.Fatal(err)
				}
				if len(a.spans()) != 0 {
					t.Fatal("an SDK span was materialized before its terminal")
				}
				if tt.disableEnable {
					disabled := beginActive(t, x, "http")
					old := currentGeneration(x)
					setEndpoint(t, x, "")
					assertJoined(t, old)
					endActive(t, x, disabled, "http")
					if x.c.Status().TerminalDisabled != 1 || x.c.Status().ActiveFlows != 1 {
						t.Fatal("disabled terminal was not removed exactly once")
					}
					setEndpoint(t, x, b.server.URL)
					endActive(t, x, disabled, "http")
					if x.c.Status().TerminalDisabled != 1 {
						t.Fatal("re-enable resurrected a completed disabled flow")
					}
					runtime.KeepAlive(disabled)
				} else {
					old := currentGeneration(x)
					if tt.viaEmpty {
						setEndpoint(t, x, "")
						assertJoined(t, old)
						old = nil
					}
					setEndpoint(t, x, b.server.URL)
					assertJoined(t, old)
				}
				var intermediate []*ownedCollector
				if tt.repeated {
					for range 2 {
						next := newOwnedCollector(t, false)
						intermediate = append(intermediate, b)
						old := currentGeneration(x)
						setEndpoint(t, x, next.server.URL)
						assertJoined(t, old)
						b = next
					}
				}
				if x.c.Status().ActiveFlows != 1 {
					t.Fatal("generation switch changed active-flow gauge")
				}
				endActive(t, x, active, tt.kind)
				if err := flushLive(t, x); err != nil {
					t.Fatal(err)
				}
				if x.c.Status().ActiveFlows != 0 || len(a.spans()) != 0 || len(b.spans()) != 1 {
					t.Fatal("terminal was not routed exactly once to the current generation")
				}
				for _, collector := range intermediate {
					if len(collector.spans()) != 0 {
						t.Fatal("retired provider received an active flow's terminal")
					}
				}
				assertWireSpan(t, b.spans()[0], tt.kind)
				x.c.mu.Lock()
				retiring := x.c.retiring
				x.c.mu.Unlock()
				if retiring != nil {
					t.Fatal("retirement remains after acknowledged switch")
				}
				runtime.KeepAlive(active)
			})
		}
	})
}

func TestTelemetryShutdown(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"stalled_collector_full_queue": {func(t *testing.T) {
			collector := newStalledCollector(t)
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, collector.server.URL)
			retained := fillStalledQueue(t, x, collector, true)
			liveHook(t, x, addon.ClientConnectedHook{})
			g := currentGeneration(x)
			started := time.Now()
			if err := x.c.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if time.Since(started) > 10*time.Second {
				t.Fatal("full-queue Close exceeded the single total budget")
			}
			assertJoined(t, g)
			collector.joined(t)
			select {
			case <-x.c.done:
			default:
				t.Fatal("controller not joined")
			}
			runtime.KeepAlive(retained)
		}},
		"repeated_close": {func(t *testing.T) {
			collector := newOwnedCollector(t, false)
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, collector.server.URL)
			liveHook(t, x, addon.ResponseHook{Flow: httpFlow(t)})
			g := currentGeneration(x)
			var group sync.WaitGroup
			results := make(chan error, 5)
			for range 5 {
				group.Go(func() { results <- x.c.Close(t.Context()) })
			}
			group.Wait()
			close(results)
			for err := range results {
				if err != nil {
					t.Error(err)
				}
			}
			assertJoined(t, g)
			if len(collector.spans()) != 1 {
				t.Fatal("repeated Close duplicated or lost a span")
			}
		}},
		"close_during_reconfigure": {func(t *testing.T) { closeWhileReplacing(t, true) }},
		"reconfigure_stalled_collector": {func(t *testing.T) {
			a, b := newStalledCollector(t), newOwnedCollector(t, false)
			x := liveController(t, Config{}, nil)
			setEndpoint(t, x, a.server.URL)
			retained := fillStalledQueue(t, x, a, true)
			active := beginActive(t, x, "http")
			old := currentGeneration(x)
			started := time.Now()
			setEndpoint(t, x, b.server.URL)
			if time.Since(started) > 10*time.Second {
				t.Fatal("retirement exceeded its single total budget")
			}
			assertJoined(t, old)
			a.joined(t)
			endActive(t, x, active, "http")
			if err := flushLive(t, x); err != nil {
				t.Fatal(err)
			}
			if len(b.spans()) != 1 {
				t.Fatal("new provider lost the active flow")
			}
			assertWireSpan(t, b.spans()[0], "http")
			runtime.KeepAlive(active)
			runtime.KeepAlive(retained)
		}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func TestTelemetryUpgrade(t *testing.T) {
	tests := map[string]struct {
		disabled            bool
		rawTCP              bool
		success             bool
		mutateAfterResponse bool
	}{
		"websocket_disabled_rawtcp":  {disabled: true, rawTCP: true},
		"websocket_disabled_close":   {disabled: true},
		"enabled_handshake_rejected": {},
		"successful_upgrade":         {success: true},
		"pending_disconnect":         {mutateAfterResponse: true},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				x := memoryController(t, Config{})
				if err := x.m.Do(t.Context(), func(ctx context.Context) error {
					return x.m.Options.Update(ctx, map[string]any{"websocket": !tt.disabled, "rawtcp": tt.rawTCP})
				}); err != nil {
					t.Fatal(err)
				}
				f := httpFlow(t)
				f.Response.StatusCode = 101
				f.Response.Headers.Set("Upgrade", "WebSocket")
				hook(t, x, addon.RequestHook{Flow: f})
				hook(t, x, addon.ResponseHook{Flow: f})
				if tt.disabled {
					span := oneSpan(t, x)
					want := expectedAttributes("http")
					want["status"] = int64(101)
					assertAttributes(t, want, span)
					if x.c.Status().ActiveFlows != 0 {
						t.Fatal("disabled upgrade kept HTTP active")
					}
					if tt.rawTCP {
						completeKind(t, x, "tcp")
						if len(flushed(t, x)) != 2 {
							t.Fatal("raw TCP fallback must be a distinct flow")
						}
					}
					return
				}
				if len(flushed(t, x)) != 0 || x.c.Status().ActiveFlows != 1 {
					t.Fatal("101 response prematurely materialized an upgrade span")
				}
				if tt.success {
					changeFlow(t, x.m, func() { f.WebSocket = &websocket.Data{TimestampEnd: new(105.25)} })
					hook(t, x, addon.WebSocketStartHook{Flow: f})
					hook(t, x, addon.WebSocketEndHook{Flow: f})
					assertAttributes(t, expectedAttributes("websocket"), oneSpan(t, x))
				} else {
					if tt.mutateAfterResponse {
						if err := x.m.Do(t.Context(), func(context.Context) error {
							f.Request.Host = "later.example"
							f.Response.TimestampEnd = new(999.0)
							return nil
						}); err != nil {
							t.Fatal(err)
						}
					}
					hook(t, x, addon.ClientDisconnectedHook{Client: f.ClientConn})
					want := expectedAttributes("http")
					want["status"] = int64(101)
					span := oneSpan(t, x)
					assertAttributes(t, want, span)
					if !span.EndTime.Equal(time.Unix(102, 750000000)) {
						t.Fatal("pending upgrade did not preserve copied response time")
					}
				}
				if x.c.Status().ActiveFlows != 0 || len(x.c.state.active) != 0 {
					t.Fatal("upgrade terminal left active state before shutdown")
				}
			})
		}
	})
}
