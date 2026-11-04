// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build proxybench

package bench

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	collectormetric "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

// ownedCollector decodes real exports and retains only bounded aggregate counts.
type ownedCollector struct {
	server   *httptest.Server
	spans    atomic.Uint64
	metrics  atomic.Uint64
	failures atomic.Uint64
}

func newOwnedCollector() *ownedCollector {
	c := new(ownedCollector)
	c.server = httptest.NewUnstartedServer(http.HandlerFunc(c.serveHTTP))
	c.server.Config.ReadHeaderTimeout = 3 * time.Second
	c.server.Config.ReadTimeout = 5 * time.Second
	c.server.Config.WriteTimeout = 5 * time.Second
	c.server.Config.IdleTimeout = 30 * time.Second
	c.server.Start()
	return c
}

func (c *ownedCollector) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-protobuf" || (r.URL.Path != "/v1/traces" && r.URL.Path != "/v1/metrics") {
		c.failures.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		c.failures.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case "/v1/traces":
		var request collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			c.failures.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				c.spans.Add(uint64(len(scope.Spans)))
			}
		}
	case "/v1/metrics":
		var request collectormetric.ExportMetricsServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			c.failures.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, resource := range request.ResourceMetrics {
			for _, scope := range resource.ScopeMetrics {
				c.metrics.Add(uint64(len(scope.Metrics)))
			}
		}
	}
	// Empty protobuf export responses acknowledge success without retained data.
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}
