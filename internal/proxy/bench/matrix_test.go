// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build proxybench

package bench

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestProxyBenchHarness(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"smoke": {run: func(t *testing.T) {
			h := newHarness(t, t.Context(), "h1", 1, 1024, false)
			if err := h.batch(); err != nil {
				t.Fatal(err)
			}
			h.checkCounts(t)
			if err := h.close(); err != nil {
				t.Fatal(err)
			}
			if got := h.completed.Load(); got != 2 {
				t.Fatalf("origin exchanges=%d, want warmup plus one measured exchange", got)
			}
		}},
		"cancel": {run: func(t *testing.T) {
			h := newHarness(t, t.Context(), "h1", 1, 1024, true)
			h.blocking.Store(true)
			done := make(chan error, 1)
			go func() { done <- h.batch() }()
			select {
			case <-h.started:
			case <-h.ctx.Done():
				t.Fatal("origin never admitted the cancellable request")
			}
			h.cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled batch=%v", err)
			}
			if err := h.close(); err != nil {
				t.Fatal(err)
			}
		}},
		"protocol": {run: func(t *testing.T) {
			for _, protocol := range []string{"h1", "h2", "h3", "ws"} {
				h := newHarness(t, t.Context(), protocol, 1, 1024, true)
				if err := h.batch(); err != nil {
					t.Fatalf("%s: %v", protocol, err)
				}
				h.checkCounts(t)
				if err := h.close(); err != nil {
					t.Fatalf("%s: %v", protocol, err)
				}
			}
		}},
		"ownership": {run: func(t *testing.T) {
			h := newHarness(t, t.Context(), "h1", 16, 1024, true)
			if err := h.batch(); err != nil {
				t.Fatal(err)
			}
			h.checkCounts(t)
			if err := h.close(); err != nil {
				t.Fatal(err)
			}
			if h.connections.Len() != 0 || h.completed.Load() != 32 {
				t.Fatalf("joined ownership: connections=%d completed=%d", h.connections.Len(), h.completed.Load())
			}
			if err := h.close(); err != nil {
				t.Fatalf("repeated close: %v", err)
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}

func TestProxyBenchMatrix(t *testing.T) {
	tests := map[string]struct{}{"h1": {}, "h2": {}, "h3": {}, "ws": {}}
	for protocol := range tests {
		t.Run(protocol, func(t *testing.T) {
			for _, count := range []int{1, 16, 256} {
				t.Run(fmt.Sprintf("connections=%d", count), func(t *testing.T) {
					for _, size := range []int{1024, 1048576} {
						t.Run(fmt.Sprintf("bytes=%d", size), func(t *testing.T) {
							for _, enabled := range []bool{false, true} {
								h := newHarness(t, t.Context(), protocol, count, size, enabled)
								for range 2 {
									if err := h.batch(); err != nil {
										t.Fatalf("telemetry=%t: %v", enabled, err)
									}
								}
								h.checkCounts(t)
								if err := h.close(); err != nil {
									t.Fatalf("telemetry=%t: %v", enabled, err)
								}
								if got, want := h.completed.Load(), int64(3*count); got != want {
									t.Fatalf("telemetry=%t: completed exchanges=%d, want %d including warmup", enabled, got, want)
								}
							}
						})
					}
				})
			}
		})
	}
}

// BenchmarkProxyThroughput measures one exchange per connection in each batch.
// WebSocket rows include normal addon dispatch with last-message-only history,
// mirroring upstream websocket_message trimming; native history otherwise grows
// with the exchange count. The same policy is used by the instrumented series.
func BenchmarkProxyThroughput(b *testing.B) {
	benchmarkProxyThroughput(b, false)
}

// BenchmarkProxyThroughputTelemetry measures the same batches with real flow
// telemetry exported to an owned healthy OTLP collector. Collector processing
// and normal exporter work are part of this diagnostic comparison's cost.
func BenchmarkProxyThroughputTelemetry(b *testing.B) {
	benchmarkProxyThroughput(b, true)
}

func benchmarkProxyThroughput(b *testing.B, enabled bool) {
	for _, protocol := range []string{"h1", "h2", "h3", "ws"} {
		b.Run(protocol, func(b *testing.B) {
			for _, count := range []int{1, 16, 256} {
				b.Run(fmt.Sprintf("connections=%d", count), func(b *testing.B) {
					for _, size := range []int{1024, 1048576} {
						b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
							h := newHarness(b, b.Context(), protocol, count, size, enabled)
							b.ReportAllocs()
							b.SetBytes(int64(count) * int64(size))
							for b.Loop() {
								if err := h.batch(); err != nil {
									b.Fatal(err)
								}
							}
							seconds := b.Elapsed().Seconds()
							requests := float64(b.N) * float64(count)
							b.ReportMetric(float64(count), "requests/op")
							b.ReportMetric(requests/seconds, "req/s")
							b.ReportMetric(requests*float64(size)/(1<<20)/seconds, "MiB/s")
							h.checkCounts(b)
							if err := h.close(); err != nil {
								b.Fatal(err)
							}
							if got, want := h.completed.Load(), int64(b.N+1)*int64(count); got != want {
								b.Fatalf("completed exchanges=%d, want %d including warmup", got, want)
							}
						})
					}
				})
			}
		})
	}
}
