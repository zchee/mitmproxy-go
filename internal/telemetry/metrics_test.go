// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/http1"
)

func collectMetrics(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var result metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTelemetryGauges(t *testing.T) {
	tests := map[string]struct{}{"connections": {}, "flows": {}, "shutdown_zero": {}, "dispatch_hold": {}, "manual_reader": {}, "low_cardinality": {}}
	t.Run("contracts", func(t *testing.T) {
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				var clients atomic.Int64
				clients.Store(7)
				counter := &http1.FidelityCounter{}
				counter.Add(19)
				x := memoryController(t, Config{Connections: func() int { return int(clients.Load()) }, Fidelity: counter})
				reader := sdkmetric.NewManualReader()
				provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithCardinalityLimit(16))
				t.Cleanup(func() {
					if err := provider.Shutdown(context.WithoutCancel(t.Context())); err != nil {
						t.Error(err)
					}
				})
				hold, err := x.c.registerMetrics(provider)
				if err != nil {
					t.Fatal(err)
				}
				x.c.admit.Lock()
				x.g.hold = hold
				x.c.admit.Unlock()
				f := httpFlow(t)
				hook(t, x, addon.RequestHook{Flow: f})
				wantClients, wantHTTP := int64(7), int64(1)
				if name == "connections" {
					clients.Store(3)
					wantClients = 3
				}
				if name == "flows" {
					hook(t, x, addon.ResponseHook{Flow: f})
					wantHTTP = 0
				}
				if name == "shutdown_zero" {
					if err := x.c.Close(t.Context()); err != nil {
						t.Fatal(err)
					}
					wantClients, wantHTTP = 0, 0
				}
				if name == "dispatch_hold" {
					x.c.OnDispatchStart()
					x.c.OnDispatchEnd()
				}
				if name == "low_cardinality" {
					for _, kind := range []string{"http", "websocket", "tcp", "udp", "dns"} {
						completeKind(t, x, kind)
					}
				}
				result := collectMetrics(t, reader)
				seen := map[string]bool{}
				for _, scope := range result.ScopeMetrics {
					for _, measurement := range scope.Metrics {
						seen[measurement.Name] = true
						switch measurement.Name {
						case "proxy.connections.active":
							gauge, ok := measurement.Data.(metricdata.Gauge[int64])
							if !ok || len(gauge.DataPoints) != 1 || gauge.DataPoints[0].Value != wantClients || gauge.DataPoints[0].Attributes.Len() != 0 {
								t.Fatalf("connection metric=%#v", measurement)
							}
						case "proxy.flows.active":
							gauge, ok := measurement.Data.(metricdata.Gauge[int64])
							if !ok || len(gauge.DataPoints) != 5 {
								t.Fatalf("flow metric=%#v", measurement)
							}
							actual := map[string]int64{}
							for _, point := range gauge.DataPoints {
								if point.Attributes.Len() != 1 {
									t.Fatalf("unbounded flow labels=%v", point.Attributes)
								}
								kind, ok := point.Attributes.Value("flow_kind")
								if !ok {
									t.Fatal("flow-kind label missing")
								}
								actual[kind.AsString()] = point.Value
							}
							if diff := gocmp.Diff(map[string]int64{"http": wantHTTP, "websocket": 0, "tcp": 0, "udp": 0, "dns": 0}, actual); diff != "" {
								t.Fatalf("active gauges (-want +got):\n%s", diff)
							}
						case "proxy.http_fidelity":
							sum, ok := measurement.Data.(metricdata.Sum[float64])
							if !ok || !sum.IsMonotonic || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 19 || sum.DataPoints[0].Attributes.Len() != 0 {
								t.Fatalf("fidelity metric=%#v", measurement)
							}
						case "proxy.dispatch.hold.duration":
							histogram, ok := measurement.Data.(metricdata.Histogram[float64])
							if !ok || len(histogram.DataPoints) != 1 || histogram.DataPoints[0].Count == 0 || histogram.DataPoints[0].Sum < 0 || histogram.DataPoints[0].Attributes.Len() != 0 {
								t.Fatalf("hold duration=%#v", measurement)
							}
						default:
							t.Errorf("unexpected metric %q", measurement.Name)
						}
					}
				}
				if len(seen) != 4 {
					t.Fatalf("metric names=%v, want exact four instruments", seen)
				}
				if name == "manual_reader" {
					again := collectMetrics(t, reader)
					if len(again.ScopeMetrics) != 1 || len(again.ScopeMetrics[0].Metrics) != 4 {
						t.Fatal("manual collection lost instruments")
					}
					result.ScopeMetrics[0].Metrics = nil
					if len(again.ScopeMetrics[0].Metrics) != 4 {
						t.Fatal("collections share their envelope storage")
					}
				}
			})
		}
	})
}
