// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"os"
	"runtime"
	"testing"
	"weak"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
)

func TestTelemetrySDKPolicy(t *testing.T) {
	tests := map[string]struct{ environment []string }{
		"hostile_sampler":          {[]string{"OTEL_TRACES_SAMPLER=always_off", "OTEL_TRACES_SAMPLER_ARG=0"}},
		"hostile_count_limit":      {[]string{"OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT=1"}},
		"hostile_value_limit":      {[]string{"OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT=1"}},
		"hostile_resource_traces":  {[]string{"OTEL_RESOURCE_ATTRIBUTES=x=y,service.name=hostile,service.version=hostile,telemetry.sdk.name=hostile,telemetry.sdk.language=hostile,telemetry.sdk.version=hostile"}},
		"hostile_resource_metrics": {[]string{"OTEL_RESOURCE_ATTRIBUTES=x=y,service.name=hostile,service.version=hostile,telemetry.sdk.name=hostile,telemetry.sdk.language=hostile,telemetry.sdk.version=hostile"}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				if os.Getenv("MITMPROXY_TELEMETRY_CHILD") == "" {
					childCase(t, tt.environment...)
					return
				}
				collector := newOwnedCollector(t, false)
				x := liveController(t, Config{Version: "test-version"}, nil)
				setEndpoint(t, x, collector.server.URL)
				f := httpFlow(t)
				f.Request.Headers.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
				liveHook(t, x, addon.ResponseHook{Flow: f})
				if err := flushLive(t, x); err != nil {
					t.Fatal(err)
				}
				spans := collector.spans()
				if len(spans) != 1 {
					t.Fatalf("hostile SDK policy produced %d spans, want one", len(spans))
				}
				assertWireSpan(t, spans[0], "http")
				if len(spans[0].Events) != 0 || len(spans[0].Links) != 0 {
					t.Fatal("exported span contains unapproved events or links")
				}
				for _, value := range spans[0].ParentSpanId {
					if value != 0 {
						t.Fatal("intercepted traceparent became a telemetry parent")
					}
				}
				want := map[string]any{"service.name": "mitmproxy-go", "service.version": "test-version", "telemetry.sdk.name": "opentelemetry", "telemetry.sdk.language": "go", "telemetry.sdk.version": "1.47.0"}
				collector.mu.Lock()
				defer collector.mu.Unlock()
				if len(collector.traces) == 0 || len(collector.metrics) == 0 {
					t.Fatal("both real OTLP signals were not observed")
				}
				for _, group := range collector.traces {
					if group.Resource == nil {
						t.Fatal("trace resource missing")
					}
					if diff := gocmp.Diff(want, wireAttributes(t, group.Resource.Attributes)); diff != "" {
						t.Fatalf("trace resource allowlist (-want +got):\n%s", diff)
					}
				}
				for _, group := range collector.metrics {
					if group.Resource == nil {
						t.Fatal("metric resource missing")
					}
					if diff := gocmp.Diff(want, wireAttributes(t, group.Resource.Attributes)); diff != "" {
						t.Fatalf("metric resource allowlist (-want +got):\n%s", diff)
					}
				}
			})
		}
	})
}

func TestTelemetryCleanup(t *testing.T) {
	tests := map[string]struct {
		run func(*testing.T, *memoryFixture)
	}{
		"active_terminal_removed": {func(t *testing.T, x *memoryFixture) {
			f := httpFlow(t)
			key := weak.Make(f.Common())
			hook(t, x, addon.RequestHook{Flow: f})
			if len(x.c.state.active) != 1 || len(x.c.state.clients) != 1 {
				t.Fatal("active state/index absent")
			}
			hook(t, x, addon.ResponseHook{Flow: f})
			if len(x.c.state.active) != 0 || len(x.c.state.clients) != 0 || x.c.Status().ActiveFlows != 0 {
				t.Fatal("terminal did not remove active state/index")
			}
			x.c.state.tombstones.mu.Lock()
			_, found := x.c.state.tombstones.completed[key]
			x.c.state.tombstones.mu.Unlock()
			if !found {
				t.Fatal("live completed identity has no deduplication tombstone")
			}
			oneSpan(t, x)
			runtime.KeepAlive(f)
		}},
		"disconnect_removed": {func(t *testing.T, x *memoryFixture) {
			f := httpFlow(t)
			hook(t, x, addon.RequestHook{Flow: f})
			hook(t, x, addon.ClientDisconnectedHook{Client: f.ClientConn})
			if len(x.c.state.active) != 0 || len(x.c.state.clients) != 0 || x.c.Status().ActiveFlows != 0 {
				t.Fatal("disconnect did not remove active state/index")
			}
			oneSpan(t, x)
			runtime.KeepAlive(f)
		}},
		"shutdown_unterminated_removed": {func(t *testing.T, x *memoryFixture) {
			completed := completeKind(t, x, "http")
			active := httpFlow(t)
			hook(t, x, addon.RequestHook{Flow: active})
			if err := x.c.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(x.c.state.active) != 0 || len(x.c.state.clients) != 0 || x.c.Status().ActiveFlows != 0 {
				t.Fatal("shutdown did not clear unterminated state/index")
			}
			x.c.state.tombstones.mu.Lock()
			count := len(x.c.state.tombstones.completed)
			stopped := x.c.state.tombstones.closed
			x.c.state.tombstones.mu.Unlock()
			if count != 0 || !stopped {
				t.Fatal("shutdown did not stop/clear cleanup registrations")
			}
			if len(flushed(t, x)) != 2 {
				t.Fatal("shutdown did not finalize the remaining flow exactly once")
			}
			runtime.KeepAlive(completed)
			runtime.KeepAlive(active)
		}},
		"completed_tombstone_removed": {func(t *testing.T, x *memoryFixture) {
			f := completeKind(t, x, "http")
			key := weak.Make(f.Common())
			registry := x.c.state.tombstones
			registry.mu.Lock()
			cleanup, found := registry.completed[key]
			registry.mu.Unlock()
			if !found {
				t.Fatal("completed tombstone missing before deterministic removal")
			}
			cleanup.Stop()
			arg := cleanupArgument{key: key, registry: registry}
			removeTombstone(arg)
			registry.mu.Lock()
			count := len(registry.completed)
			registry.mu.Unlock()
			if count != 0 || x.c.Status().ActiveFlows != 0 {
				t.Fatal("cleanup changed lifecycle state or retained its tombstone")
			}
			if err := x.c.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			removeTombstone(arg)
			removeTombstone(arg)
			registry.mu.Lock()
			count = len(registry.completed)
			registry.mu.Unlock()
			if count != 0 {
				t.Fatal("late cleanup resurrected a tombstone")
			}
			runtime.KeepAlive(f)
		}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) { tt.run(t, memoryController(t, Config{Version: "test"})) })
		}
	})
}
