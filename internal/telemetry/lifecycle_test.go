// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"math"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"weak"

	"go.opentelemetry.io/otel/codes"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/http1"
)

func TestTelemetryFlows(t *testing.T) {
	tests := map[string]struct{}{"http": {}, "websocket": {}, "tcp": {}, "udp": {}, "dns": {}}
	t.Run("kinds", func(t *testing.T) {
		for kind := range tests {
			t.Run(kind, func(t *testing.T) {
				x := memoryController(t, Config{Version: "test"})
				f := completeKind(t, x, kind)
				span := oneSpan(t, x)
				if span.Name != "proxy.flow."+kind {
					t.Errorf("span name=%q", span.Name)
				}
				assertAttributes(t, expectedAttributes(kind), span)
				if x.c.Status().ActiveFlows != 0 {
					t.Fatal("terminal left an active flow")
				}
				runtime.KeepAlive(f)
			})
		}
	})
}

func TestTelemetryLifecycle(t *testing.T) {
	tests := map[string]struct {
		run func(*testing.T, *memoryFixture)
	}{
		"terminal_first_error": {func(t *testing.T, x *memoryFixture) {
			client, server := clientAndServer()
			f := flow.NewHTTPFlow(client, server, true)
			f.Error = &flow.Error{Msg: "private error", Timestamp: 102.75}
			hook(t, x, addon.ErrorHook{Flow: f})
			span := oneSpan(t, x)
			if span.Status.Code != codes.Error {
				t.Error("terminal-first error was not classified as error")
			}
			assertAttributes(t, map[string]any{"mode": "regular", "flow_kind": "http", "http_fidelity": "0", "timing_known": false, "request_size_known": false, "response_size_known": false}, span)
		}},
		"response_then_error": {func(t *testing.T, x *memoryFixture) {
			f := completeKind(t, x, "http").(*flow.HTTPFlow)
			changeFlow(t, x.m, func() { f.Error = &flow.Error{Msg: "later error", Timestamp: 103} })
			hook(t, x, addon.ErrorHook{Flow: f})
			span := oneSpan(t, x)
			assertAttributes(t, expectedAttributes("http"), span)
			if span.Status.Code != codes.Unset {
				t.Error("later error changed a completed span")
			}
		}},
		"error_then_end": {func(t *testing.T, x *memoryFixture) {
			client, server := clientAndServer()
			f := flow.NewTCPFlow(client, server, true)
			hook(t, x, addon.TCPStartHook{Flow: f})
			changeFlow(t, x.m, func() { f.Error = &flow.Error{Msg: "private", Timestamp: 102.75} })
			hook(t, x, addon.TCPErrorHook{Flow: f})
			hook(t, x, addon.TCPEndHook{Flow: f})
			if oneSpan(t, x).Status.Code != codes.Error {
				t.Error("TCP error classification missing")
			}
		}},
		"websocket_upgrade": {func(t *testing.T, x *memoryFixture) {
			completeKind(t, x, "websocket")
			assertAttributes(t, expectedAttributes("websocket"), oneSpan(t, x))
		}},
		"connect_tunnel": {func(t *testing.T, x *memoryFixture) {
			f := httpFlow(t)
			f.Request.Method = "CONNECT"
			hook(t, x, addon.HTTPConnectHook{Flow: f})
			hook(t, x, addon.HTTPConnectedHook{Flow: f})
			hook(t, x, addon.ResponseHook{Flow: f})
			completeKind(t, x, "tcp")
			spans := flushed(t, x)
			if len(spans) != 2 || spans[0].Name != "proxy.flow.http" || spans[1].Name != "proxy.flow.tcp" {
				t.Fatalf("CONNECT/tunnel spans=%v", spans)
			}
		}},
		"duplicate_terminal": {func(t *testing.T, x *memoryFixture) {
			f := completeKind(t, x, "http").(*flow.HTTPFlow)
			for range 3 {
				hook(t, x, addon.ResponseHook{Flow: f})
				hook(t, x, addon.RequestHook{Flow: f})
			}
			oneSpan(t, x)
			if x.c.Status().ActiveFlows != 0 {
				t.Error("duplicate observation reopened the flow")
			}
		}},
		"reused_external_id": {func(t *testing.T, x *memoryFixture) {
			first := completeKind(t, x, "http")
			second := httpFlow(t)
			second.ID = first.Common().ID
			hook(t, x, addon.ResponseHook{Flow: second})
			if got := len(flushed(t, x)); got != 2 {
				t.Fatalf("distinct objects sharing external ID produced %d spans, want 2", got)
			}
			runtime.KeepAlive(first)
		}},
		"replay_timestamps": {func(t *testing.T, x *memoryFixture) {
			f := httpFlow(t)
			f.IsReplay = new("response")
			hook(t, x, addon.ResponseHook{Flow: f})
			span := oneSpan(t, x)
			if !span.StartTime.Equal(time.Unix(100, 250000000)) || !span.EndTime.Equal(time.Unix(102, 750000000)) {
				t.Fatalf("SDK timestamps=%v..%v", span.StartTime, span.EndTime)
			}
		}},
		"shutdown_active": {func(t *testing.T, x *memoryFixture) {
			f := httpFlow(t)
			hook(t, x, addon.RequestHook{Flow: f})
			if x.c.Status().ActiveFlows != 1 {
				t.Fatal("request did not open flow")
			}
			if err := x.c.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			span := oneSpan(t, x)
			if span.Status.Code != codes.Error || x.c.Status().ActiveFlows != 0 || len(x.c.state.active) != 0 {
				t.Fatal("shutdown did not finalize copied active state")
			}
		}},
		"weak_retention": {func(t *testing.T, x *memoryFixture) {
			f := httpFlow(t)
			key := weak.Make(f.Common())
			hook(t, x, addon.RequestHook{Flow: f})
			runtime.GC()
			if key.Value() != f.Common() {
				t.Fatal("live flow's weak identity changed")
			}
			entry := x.c.state.active[key]
			if entry == nil {
				t.Fatal("active scalar entry disappeared through GC")
			}
			for _, value := range []any{entry, cleanupArgument{}, tombstoneRegistry{}} {
				typ := reflect.TypeOf(value)
				if typ.Kind() == reflect.Pointer {
					typ = typ.Elem()
				}
				for field := range typ.Fields() {
					if field.Type == reflect.TypeFor[*flow.Base]() || field.Type == reflect.TypeFor[*flow.HTTPFlow]() || field.Type == reflect.TypeFor[flow.Flow]() || field.Type == reflect.TypeFor[*Controller]() {
						t.Fatalf("non-owning state has strong retention field %s", field.Name)
					}
				}
			}
			hook(t, x, addon.ResponseHook{Flow: f})
			oneSpan(t, x)
			runtime.KeepAlive(f)
		}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) { tt.run(t, memoryController(t, Config{Version: "test"})) })
		}
	})
}

func TestTelemetryAttributes(t *testing.T) {
	tests := map[string]struct {
		run func(*testing.T, *memoryFixture, *flow.HTTPFlow, map[string]any)
	}{
		"mode_kind": {func(_ *testing.T, _ *memoryFixture, f *flow.HTTPFlow, want map[string]any) {
			f.ClientConn.ProxyMode = "reverse:https://user:password@example.test/path"
			want["mode"] = "reverse"
		}},
		"method_host_status": {func(_ *testing.T, _ *memoryFixture, f *flow.HTTPFlow, want map[string]any) {
			f.Request.Method = "POST"
			f.Request.Host = "api.example.test"
			f.Response.StatusCode = 418
			want["method"] = "POST"
			want["host"] = "api.example.test"
			want["status"] = int64(418)
		}},
		"raw_sizes": {func(_ *testing.T, _ *memoryFixture, f *flow.HTTPFlow, want map[string]any) {
			f.Request.RawContent = []byte{0x1f, 0x8b}
			f.Request.Headers.Set("Content-Length", "9000")
			f.Request.Headers.Set("Content-Encoding", "gzip")
			want["request_body_bytes"] = int64(2)
		}},
		"streamed_unknown": {func(_ *testing.T, _ *memoryFixture, f *flow.HTTPFlow, want map[string]any) {
			f.Request.RawContent = nil
			f.Response.RawContent = nil
			f.Request.Headers.Set("Content-Length", "9000")
			want["request_size_known"] = false
			want["response_size_known"] = false
			delete(want, "request_body_bytes")
			delete(want, "response_body_bytes")
		}},
		"empty_known": {func(_ *testing.T, _ *memoryFixture, f *flow.HTTPFlow, want map[string]any) {
			f.Request.RawContent = []byte{}
			f.Response.RawContent = []byte{}
			want["request_body_bytes"] = int64(0)
			want["response_body_bytes"] = int64(0)
		}},
		"timestamps_missing": {func(_ *testing.T, _ *memoryFixture, f *flow.HTTPFlow, want map[string]any) {
			f.Request.TimestampStart = 0
			f.Request.TimestampEnd = nil
			f.Response.TimestampStart = 0
			f.Response.TimestampEnd = nil
			f.ClientConn.TimestampStart = nil
			f.ClientConn.TimestampEnd = nil
			for key := range want {
				if strings.HasSuffix(key, "_seconds") {
					delete(want, key)
				}
			}
			want["timing_known"] = false
		}},
		"timestamps_invalid": {func(_ *testing.T, _ *memoryFixture, f *flow.HTTPFlow, want map[string]any) {
			f.Request.TimestampStart = math.NaN()
			f.Request.TimestampEnd = new(math.Inf(1))
			f.Response.TimestampStart = 102
			f.Response.TimestampEnd = new(101.0)
			for key := range want {
				if strings.HasSuffix(key, "_seconds") {
					delete(want, key)
				}
			}
			want["response_start_unix_seconds"] = 102.0
			want["timing_known"] = false
		}},
		"non_http_absence": {func(t *testing.T, x *memoryFixture, _ *flow.HTTPFlow, _ map[string]any) {
			for _, kind := range []string{"tcp", "udp", "dns"} {
				completeKind(t, x, kind)
			}
			spans := flushed(t, x)
			if len(spans) != 3 {
				t.Fatalf("non-HTTP spans=%d", len(spans))
			}
			for i, kind := range []string{"tcp", "udp", "dns"} {
				assertAttributes(t, expectedAttributes(kind), spans[i])
			}
		}},
		"fidelity_instance": {func(t *testing.T, x *memoryFixture, _ *flow.HTTPFlow, want map[string]any) {
			count := uint64(1)<<53 | 7
			x.c.cfg.Fidelity.Add(count)
			if x.c.Status().HTTPFidelity != count {
				t.Fatal("local diagnostic fidelity count lost precision")
			}
			want["http_fidelity"] = strconv.FormatUint(count, 10)
		}},
		"privacy_bounds": {func(_ *testing.T, _ *memoryFixture, f *flow.HTTPFlow, want map[string]any) {
			f.Request.Method = strings.Repeat("M", 65)
			f.Request.Host = strings.Repeat("h", 254)
			f.Request.Headers.Set("Authorization", "private-token")
			f.Request.Headers.Set("Cookie", "private-cookie")
			f.Request.Path = "/private?password=secret"
			f.Comment = "private comment"
			f.ClientConn.ProxyMode = "reverse:https://user:secret@example.test/private"
			want["mode"] = "reverse"
			delete(want, "method")
			delete(want, "host")
		}},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				x := memoryController(t, Config{Version: "test", Fidelity: &http1.FidelityCounter{}})
				f := httpFlow(t)
				want := expectedAttributes("http")
				tt.run(t, x, f, want)
				if name == "non_http_absence" {
					return
				}
				hook(t, x, addon.RequestHook{Flow: f})
				hook(t, x, addon.ResponseHook{Flow: f})
				span := oneSpan(t, x)
				assertAttributes(t, want, span)
				if span.EndTime.Before(span.StartTime) {
					t.Fatal("invalid SDK lifecycle fallback")
				}
				if name == "privacy_bounds" && x.c.Status().InvalidMetadata < 2 {
					t.Fatal("invalid scalar metadata was not diagnosed")
				}
			})
		}
	})
}
