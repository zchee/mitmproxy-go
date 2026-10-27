// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package debugserver

import (
	"encoding/json/jsontext"
	"runtime/metrics"
	"slices"

	"github.com/zchee/mitmproxy-go/internal/telemetry"
)

type metricNumber float64

// MarshalJSONTo writes finite numbers and explicit nonfinite string markers.
func (n metricNumber) MarshalJSONTo(encoder *jsontext.Encoder) error {
	return encoder.WriteToken(jsontext.Float(float64(n)))
}

type metricHistogram struct {
	Counts []uint64       `json:"counts"`
	Bounds []metricNumber `json:"bounds"`
}

type metricSample struct {
	Name      string           `json:"name"`
	Kind      string           `json:"kind"`
	Uint64    *uint64          `json:"uint64,omitzero"`
	Float64   *metricNumber    `json:"float64,omitzero"`
	Histogram *metricHistogram `json:"histogram,omitzero"`
}

type runtimeSnapshot struct {
	Runtime     []metricSample   `json:"runtime"`
	Telemetry   telemetry.Status `json:"telemetry"`
	Diagnostics Status           `json:"diagnostics"`
}

func copySample(source metrics.Sample) metricSample {
	result := metricSample{Name: source.Name}
	switch source.Value.Kind() {
	case metrics.KindUint64:
		result.Kind = "uint64"
		result.Uint64 = new(source.Value.Uint64())
	case metrics.KindFloat64:
		result.Kind = "float64"
		result.Float64 = new(metricNumber(source.Value.Float64()))
	case metrics.KindFloat64Histogram:
		result.Kind = "histogram"
		histogram := source.Value.Float64Histogram()
		bounds := make([]metricNumber, len(histogram.Buckets))
		for i, value := range histogram.Buckets {
			bounds[i] = metricNumber(value)
		}
		result.Histogram = &metricHistogram{Counts: slices.Clone(histogram.Counts), Bounds: bounds}
	default:
		result.Kind = "unsupported"
	}
	return result
}

func readSnapshot(status Status, counters telemetry.Status) runtimeSnapshot {
	descriptions := metrics.All()
	// Each response owns fresh samples and copies histograms before another
	// runtime read can replace their backing storage.
	samples := make([]metrics.Sample, len(descriptions))
	for i, description := range descriptions {
		samples[i].Name = description.Name
	}
	metrics.Read(samples)
	result := runtimeSnapshot{Runtime: make([]metricSample, len(samples)), Telemetry: counters, Diagnostics: status}
	for i, sample := range samples {
		result.Runtime[i] = copySample(sample)
	}
	return result
}
