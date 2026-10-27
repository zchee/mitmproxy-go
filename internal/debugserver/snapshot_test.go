// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package debugserver

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"maps"
	"math"
	"runtime/metrics"
	"slices"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/telemetry"
)

func TestDebugSnapshot(t *testing.T) {
	t.Run("kinds", func(t *testing.T) {
		tests := map[string]struct {
			name string
			kind metrics.ValueKind
		}{
			"uint64":      {name: "/sched/gomaxprocs:threads", kind: metrics.KindUint64},
			"float64":     {name: "/cpu/classes/gc/total:cpu-seconds", kind: metrics.KindFloat64},
			"histogram":   {name: "/gc/heap/allocs-by-size:bytes", kind: metrics.KindFloat64Histogram},
			"unsupported": {name: "/owned-unsupported-metric", kind: metrics.KindBad},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				samples := []metrics.Sample{{Name: tt.name}}
				metrics.Read(samples)
				if actual := samples[0].Value.Kind(); actual != tt.kind {
					t.Fatalf("real runtime metric %q kind=%v, want %v", tt.name, actual, tt.kind)
				}
				actual := copySample(samples[0])
				if actual.Kind != name {
					t.Fatalf("schema kind=%q, want %q", actual.Kind, name)
				}
				switch tt.kind {
				case metrics.KindUint64:
					if actual.Uint64 == nil || *actual.Uint64 != samples[0].Value.Uint64() || actual.Float64 != nil || actual.Histogram != nil {
						t.Fatal("uint64 scalar changed or leaked another representation")
					}
				case metrics.KindFloat64:
					if actual.Float64 == nil || float64(*actual.Float64) != samples[0].Value.Float64() || actual.Uint64 != nil || actual.Histogram != nil {
						t.Fatal("float64 scalar changed or leaked another representation")
					}
				case metrics.KindFloat64Histogram:
					source := samples[0].Value.Float64Histogram()
					if actual.Histogram == nil || actual.Uint64 != nil || actual.Float64 != nil {
						t.Fatal("histogram representation missing or ambiguous")
					}
					if diff := gocmp.Diff(source.Counts, actual.Histogram.Counts); diff != "" {
						t.Fatal(diff)
					}
					for i, bound := range source.Buckets {
						if float64(actual.Histogram.Bounds[i]) != bound {
							t.Fatalf("bucket %d changed", i)
						}
					}
					before := slices.Clone(source.Counts)
					actual.Histogram.Counts[0]++
					if diff := gocmp.Diff(before, source.Counts); diff != "" {
						t.Fatalf("histogram shares runtime backing: %s", diff)
					}
				case metrics.KindBad:
					if actual.Uint64 != nil || actual.Float64 != nil || actual.Histogram != nil {
						t.Fatal("unsupported metric contains a scalar or histogram")
					}
				}
				if _, err := json.Marshal(actual); err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal([]metricNumber{metricNumber(math.Inf(-1)), 0, metricNumber(math.Inf(1)), metricNumber(math.NaN())})
				if err != nil || string(encoded) != `["-Infinity",0,"Infinity","NaN"]` {
					t.Fatalf("nonfinite encoding=%s, error=%v", encoded, err)
				}
			})
		}
	})
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"concurrent_ownership": {run: func(t *testing.T) {
				baseline := readSnapshot(Status{}, telemetry.Status{})
				before, err := json.Marshal(baseline)
				if err != nil {
					t.Fatal(err)
				}
				var workers sync.WaitGroup
				for range 16 {
					workers.Go(func() {
						result := readSnapshot(Status{}, telemetry.Status{})
						for _, sample := range result.Runtime {
							if sample.Histogram != nil && len(sample.Histogram.Counts) > 0 {
								sample.Histogram.Counts[0]++
							}
						}
						if _, err := json.Marshal(result); err != nil {
							t.Error(err)
						}
					})
				}
				workers.Wait()
				after, err := json.Marshal(baseline)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("concurrent reads changed retained response: %v", err)
				}
			}},
			"no_flow_data": {run: func(t *testing.T) {
				result := readSnapshot(Status{}, telemetry.Status{ActiveFlows: 3, HTTPFidelity: 1<<60 + 1})
				encoded, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				var document map[string]jsontext.Value
				if err := json.Unmarshal(encoded, &document); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff([]string{"diagnostics", "runtime", "telemetry"}, slices.Sorted(maps.Keys(document))); diff != "" {
					t.Fatalf("unexpected diagnostics surface: %s", diff)
				}
				for _, forbidden := range [][]byte{[]byte(`"headers"`), []byte(`"body"`), []byte(`"options"`), []byte(`"environment"`), []byte(`"resource"`), []byte(`"flows"`)} {
					if bytes.Contains(encoded, forbidden) {
						t.Fatalf("private data category exposed: %s", forbidden)
					}
				}
				var decoded struct {
					Telemetry telemetry.Status `json:"telemetry"`
				}
				if err := json.Unmarshal(encoded, &decoded); err != nil {
					t.Fatal(err)
				}
				if decoded.Telemetry.HTTPFidelity != 1<<60+1 || decoded.Telemetry.ActiveFlows != 3 {
					t.Fatalf("typed low-cardinality counters changed: %+v", decoded.Telemetry)
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}
