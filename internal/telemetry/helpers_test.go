// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	metriccollector "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracecollector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	metricpb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

type ownedCollector struct {
	server  *httptest.Server
	mu      sync.Mutex
	traces  []*tracepb.ResourceSpans
	metrics []*metricpb.ResourceMetrics
	paths   []string
	headers []http.Header
}

func newOwnedCollector(t *testing.T, tls bool) *ownedCollector {
	t.Helper()
	c := &ownedCollector{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(data) > 1<<20 {
			t.Errorf("collector request exceeds bounds or read failed: %v", err)
			w.WriteHeader(400)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.paths = append(c.paths, r.URL.Path)
		c.headers = append(c.headers, r.Header.Clone())
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/traces"):
			var request tracecollector.ExportTraceServiceRequest
			if err := proto.Unmarshal(data, &request); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			c.traces = append(c.traces, request.ResourceSpans...)
		case strings.HasSuffix(r.URL.Path, "/v1/metrics"):
			var request metriccollector.ExportMetricsServiceRequest
			if err := proto.Unmarshal(data, &request); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			c.metrics = append(c.metrics, request.ResourceMetrics...)
		default:
			t.Errorf("unexpected collector path: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(200)
	})
	if tls {
		c.server = httptest.NewTLSServer(handler)
	} else {
		c.server = httptest.NewServer(handler)
	}
	t.Cleanup(c.server.Close)
	return c
}

func (c *ownedCollector) spans() []*tracepb.Span {
	c.mu.Lock()
	defer c.mu.Unlock()
	var spans []*tracepb.Span
	for _, resource := range c.traces {
		for _, scope := range resource.ScopeSpans {
			spans = append(spans, scope.Spans...)
		}
	}
	return spans
}

type memoryFixture struct {
	c        *Controller
	m        *master.Master
	g        *generation
	exporter *tracetest.InMemoryExporter
}

func memoryController(t *testing.T, cfg Config) *memoryFixture {
	t.Helper()
	collector := newOwnedCollector(t, false)
	c := New(cfg)
	m := master.New(master.Config{OnHookComplete: c.OnHookComplete, OnDispatchStart: c.OnDispatchStart, OnDispatchEnd: c.OnDispatchEnd})
	c.Bind(m)
	exporter := tracetest.NewInMemoryExporter()
	client, transport := newHTTPClient(nil, nil)
	metrics, err := otlpmetrichttp.New(t.Context(), otlpmetrichttp.WithEndpointURL(collector.server.URL+"/v1/metrics"), otlpmetrichttp.WithHTTPClient(client), otlpmetrichttp.WithHeaders(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.generationWithExporters("memory", exporter, metrics)
	if err != nil {
		t.Fatal(err)
	}
	g.transport = transport
	c.current = g
	fixture := &memoryFixture{c: c, m: m, g: g, exporter: exporter}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
		grace, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		if err := g.stop(ctx, grace); err != nil {
			t.Error(err)
		}
		if len(collector.spans()) != 0 {
			t.Error("in-memory trace fixture unexpectedly exported HTTP traces")
		}
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return fixture
}

func hook(t *testing.T, fixture *memoryFixture, event addon.Hook) {
	t.Helper()
	if err := fixture.m.Addons.Hook(t.Context(), event); err != nil {
		t.Fatal(err)
	}
}

func changeFlow(t *testing.T, m *master.Master, change func()) {
	t.Helper()
	if err := m.Do(t.Context(), func(context.Context) error {
		change()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func flushed(t *testing.T, fixture *memoryFixture) tracetest.SpanStubs {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := fixture.g.traces.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
	return fixture.exporter.GetSpans()
}

func oneSpan(t *testing.T, fixture *memoryFixture) tracetest.SpanStub {
	t.Helper()
	spans := flushed(t, fixture)
	if len(spans) != 1 {
		t.Fatalf("completed spans=%d, want exactly one", len(spans))
	}
	return spans[0]
}

func attributeMap(attrs []attribute.KeyValue) map[string]any {
	result := make(map[string]any, len(attrs))
	for _, item := range attrs {
		result[string(item.Key)] = item.Value.AsInterface()
	}
	return result
}

func clientAndServer() (*connection.Client, *connection.Server) {
	client := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 1234}, connection.Address{Host: "127.0.0.1", Port: 8080}, 100.25)
	client.TimestampEnd = new(102.75)
	return client, connection.NewServer(&connection.Address{Host: "example.test", Port: 443})
}

func httpFlow(t *testing.T) *flow.HTTPFlow {
	t.Helper()
	client, server := clientAndServer()
	f := flow.NewHTTPFlow(client, server, true)
	var err error
	f.Request, err = httpmsg.MakeRequest("GET", "https://example.test/private?token=not-exported", []byte("req"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Response, err = httpmsg.MakeResponse(200, []byte("reply"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Request.TimestampStart, f.Request.TimestampEnd = 100.25, new(100.75)
	f.Response.TimestampStart, f.Response.TimestampEnd = 101.25, new(102.75)
	return f
}

func completeKind(t *testing.T, fixture *memoryFixture, kind string) flow.Flow {
	t.Helper()
	client, server := clientAndServer()
	switch kind {
	case "http":
		f := httpFlow(t)
		hook(t, fixture, addon.RequestHook{Flow: f})
		hook(t, fixture, addon.ResponseHook{Flow: f})
		return f
	case "websocket":
		f := httpFlow(t)
		f.Response.StatusCode = 101
		f.Response.Headers.Set("Upgrade", "websocket")
		f.WebSocket = &websocket.Data{TimestampEnd: new(105.25)}
		hook(t, fixture, addon.RequestHook{Flow: f})
		hook(t, fixture, addon.ResponseHook{Flow: f})
		hook(t, fixture, addon.WebSocketStartHook{Flow: f})
		hook(t, fixture, addon.WebSocketEndHook{Flow: f})
		return f
	case "tcp":
		f := flow.NewTCPFlow(client, server, true)
		hook(t, fixture, addon.TCPStartHook{Flow: f})
		changeFlow(t, fixture.m, func() { f.Messages = append(f.Messages, tcp.NewMessage(true, []byte("req"))) })
		hook(t, fixture, addon.TCPMessageHook{Flow: f})
		changeFlow(t, fixture.m, func() { f.Messages = append(f.Messages, tcp.NewMessage(false, []byte("reply"))) })
		hook(t, fixture, addon.TCPMessageHook{Flow: f})
		hook(t, fixture, addon.TCPEndHook{Flow: f})
		return f
	case "udp":
		f := flow.NewUDPFlow(client, server, true)
		hook(t, fixture, addon.UDPStartHook{Flow: f})
		changeFlow(t, fixture.m, func() { f.Messages = append(f.Messages, udp.NewMessage(true, []byte("req"))) })
		hook(t, fixture, addon.UDPMessageHook{Flow: f})
		changeFlow(t, fixture.m, func() { f.Messages = append(f.Messages, udp.NewMessage(false, []byte("reply"))) })
		hook(t, fixture, addon.UDPMessageHook{Flow: f})
		hook(t, fixture, addon.UDPEndHook{Flow: f})
		return f
	case "dns":
		f := flow.NewDNSFlow(client, server, true)
		f.Request = &dns.Message{Timestamp: new(100.25)}
		f.Response = &dns.Message{Timestamp: new(102.75)}
		hook(t, fixture, addon.DNSRequestHook{Flow: f})
		hook(t, fixture, addon.DNSResponseHook{Flow: f})
		return f
	default:
		t.Fatalf("unknown fixture kind %q", kind)
		return nil
	}
}

func expectedAttributes(kind string) map[string]any {
	result := map[string]any{"mode": "regular", "flow_kind": kind, "http_fidelity": "0", "flow_start_unix_seconds": 100.25, "flow_end_unix_seconds": 102.75, "flow_duration_seconds": 2.5, "timing_known": true}
	switch kind {
	case "http", "websocket":
		maps.Copy(result, map[string]any{"method": "GET", "host": "example.test", "status": int64(200), "request_body_bytes": int64(3), "response_body_bytes": int64(5), "request_size_known": true, "response_size_known": true, "request_start_unix_seconds": 100.25, "request_end_unix_seconds": 100.75, "request_duration_seconds": 0.5, "response_start_unix_seconds": 101.25, "response_end_unix_seconds": 102.75, "response_duration_seconds": 1.5})
		if kind == "websocket" {
			result["status"] = int64(101)
			result["websocket_end_unix_seconds"] = 105.25
			result["flow_end_unix_seconds"] = 105.25
			result["flow_duration_seconds"] = 5.0
		}
	case "tcp", "udp":
		result["host"], result["client_message_bytes"], result["server_message_bytes"], result["message_size_known"] = "example.test", int64(3), int64(5), true
	case "dns":
		result["host"], result["dns_request_unix_seconds"], result["dns_response_unix_seconds"] = "example.test", 100.25, 102.75
		result["request_size_known"], result["response_size_known"] = false, false
	}
	return result
}

func assertAttributes(t *testing.T, want map[string]any, span tracetest.SpanStub) {
	t.Helper()
	if diff := gocmp.Diff(want, attributeMap(span.Attributes)); diff != "" {
		t.Fatalf("complete attribute key/type/value set (-want +got):\n%s", diff)
	}
}
